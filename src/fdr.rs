//! FDR control v2 and the TCP proxy used by restoreOS to recover device factory data.
mod protocol;
use crate::mux::{MuxStream, Session};
use anyhow::{Context, Result, bail, ensure};
pub use protocol::validate_proxy_target;
use protocol::{connection_handshake, control_handshake, ping, proxy_handshake, read_exact_idle};
use std::{
    io::{Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const IDLE_TIMEOUT: Duration = Duration::from_secs(1);
const RELAY_TIMEOUT: Duration = Duration::from_millis(100);
const RELAY_BUFFER: usize = 32_768;
const MAX_CONNECTIONS: usize = 64;

pub struct Fdr {
    session: Session,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    errors: mpsc::Receiver<String>,
}

impl Fdr {
    pub fn start(session: &Session) -> Result<Self> {
        let (mut control, port, version) = negotiate(session)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker_session = session.clone();
        let (sender, errors) = mpsc::channel();
        let worker =
            thread::Builder::new()
                .name("zalivka-fdr".into())
                .spawn(crate::progress::inherit(move || {
                    let mut children: Vec<JoinHandle<()>> = Vec::new();
                    let result = control_loop(
                        &mut control,
                        port,
                        version,
                        &worker_session,
                        &worker_stop,
                        &mut children,
                    );
                    if let Err(error) = result
                        && !worker_stop.load(Ordering::Relaxed)
                    {
                        crate::log!(Error, "fdr:control", "{error:#}");
                        let _ = sender.send(format!("FDR control failed: {error:#}"));
                        worker_session.cancel();
                    }
                    // EOF on control also ends its proxy children. Otherwise idle
                    // children can keep this worker blocked in join indefinitely.
                    worker_stop.store(true, Ordering::Relaxed);
                    for child in children {
                        let _ = child.join();
                    }
                    crate::log!(Trace, "fdr:control", "Stopped");
                }))?;
        Ok(Self {
            session: session.clone(),
            stop,
            worker: Some(worker),
            errors,
        })
    }

    pub fn check(&self) -> Result<()> {
        if let Ok(error) = self.errors.try_recv() {
            bail!("{error}");
        }
        Ok(())
    }

    /// Final restore status ends FDR work. Suppress teardown errors without
    /// cancelling the shared session while its main channel acknowledges status.
    pub fn stop(&self) {
        crate::log!(Trace, "fdr:control", "Stopping");
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Prefer FDR v2 and fall back to v1 only when the version-2 handshake fails.
fn negotiate(session: &Session) -> Result<(MuxStream, u16, u8)> {
    match control_handshake(session, 2) {
        Ok((control, port)) => Ok((control, port, 2)),
        Err(error) => {
            crate::log!(Debug, "fdr:control", "v2: {error:#}; falling back to v1");
            let (control, port) = control_handshake(session, 1)?;
            Ok((control, port, 1))
        }
    }
}

fn control_loop(
    control: &mut MuxStream,
    port: u16,
    version: u8,
    session: &Session,
    stop: &Arc<AtomicBool>,
    children: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    let mut sync_id = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let mut command = [0; 2];
        if !read_exact_idle(control, &mut command, stop)? {
            break;
        }
        crate::log!(
            Trace,
            "fdr:control",
            "Command={:#06x}",
            u16::from_le_bytes(command)
        );
        match u16::from_le_bytes(command) {
            1 => {
                if !read_exact_idle(control, &mut command, stop)? {
                    ensure!(stop.load(Ordering::Relaxed), "FDR sync command truncated");
                    break;
                }
                reap_children(children)?;
                ensure!(
                    children.len() < MAX_CONNECTIONS,
                    "too many active FDR connections"
                );
                sync_id += 1;
                crate::log!(Debug, "fdr:conn", "Sync {sync_id}: port={port}");
                // Match the reference Sync ordering: complete HelloConn
                // before accepting another Sync. Only proxy handling is
                // concurrent; parallel connects could reorder requests.
                let connection = connect_connection(session, port, version);
                let connection = match connection {
                    Ok(connection) => connection,
                    Err(error) => {
                        if !stop.load(Ordering::Relaxed) {
                            crate::log!(Warning, "fdr:conn", "Sync {sync_id}: {error:#}");
                        }
                        continue;
                    }
                };
                crate::log!(Debug, "fdr:conn", "Sync {sync_id}: HelloConn complete");
                let child_stop = Arc::clone(stop);
                let child_id = sync_id;
                children.push(
                    thread::Builder::new()
                        .name("zalivka-fdr-connection".into())
                        .spawn(crate::progress::inherit(move || {
                            let result =
                                handle_connection(connection, &child_stop, crate::proxy::connect);
                            // FDR connections have independent lifetimes. The
                            // device can close one or request a replacement;
                            // restored's final status decides restore success.
                            if let Err(error) = result
                                && !child_stop.load(Ordering::Relaxed)
                            {
                                crate::log!(
                                    Warning,
                                    "fdr:conn",
                                    "Sync {child_id}, port {port}: {error:#}"
                                );
                            } else if !child_stop.load(Ordering::Relaxed) {
                                crate::log!(Debug, "fdr:conn", "Sync {child_id}: closed");
                            }
                        }))?,
                );
            }
            0xbbaa => ping(control)?,
            command => bail!("unsupported FDR control command {command:#x}"),
        }
    }
    Ok(())
}

fn reap_children(children: &mut Vec<JoinHandle<()>>) -> Result<()> {
    for child in children.extract_if(.., |child| child.is_finished()) {
        child
            .join()
            .map_err(|_| anyhow::anyhow!("FDR worker panicked"))?;
    }
    Ok(())
}

fn connect_connection(session: &Session, port: u16, version: u8) -> Result<MuxStream> {
    let mut connection = session.connect(port)?;
    connection.set_log_source("fdr:conn");
    connection.set_read_timeout(HANDSHAKE_TIMEOUT);
    connection.write_all(b"HelloConn\0")?;
    connection_handshake(&mut connection, version).context("FDR connection handshake")?;
    Ok(connection)
}

impl Drop for Fdr {
    fn drop(&mut self) {
        self.stop();
        self.session.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(crate) fn handle_connection<S: Read + Write>(
    mut stream: MuxStream,
    stop: &AtomicBool,
    mut connect: impl FnMut(&str, u16) -> Result<S>,
) -> Result<()> {
    stream.set_log_source("fdr:conn");
    let channel = stream.local_port();
    stream.set_read_timeout(IDLE_TIMEOUT);
    let mut command = [0; 2];
    while read_exact_idle(&mut stream, &mut command, stop)
        .context("reading FDR connection command")?
    {
        crate::log!(
            Trace,
            "fdr:conn",
            "Command={:#06x}",
            u16::from_le_bytes(command)
        );
        match u16::from_le_bytes(command) {
            0xbbaa => {
                crate::log!(Trace, "fdr:conn", "Ping");
                stream.set_read_timeout(HANDSHAKE_TIMEOUT);
                ping(&mut stream)?;
                stream.set_read_timeout(IDLE_TIMEOUT);
            }
            _ if command[0] == 5 && command[1] != 0 => {
                stream.set_read_timeout(HANDSHAKE_TIMEOUT);
                let (host, port, mut socket) =
                    proxy_handshake(&mut stream, command[1], |host, port| {
                        crate::log!(Debug, "fdr:proxy", "Connecting to {host}:{port}");
                        let started = Instant::now();
                        let socket = connect(host, port)?;
                        crate::log!(
                            Debug,
                            "fdr:proxy",
                            "{host}:{port}: connected in {:.3} s",
                            started.elapsed().as_secs_f64()
                        );
                        Ok(socket)
                    })?;
                stream.set_read_timeout(RELAY_TIMEOUT);
                return relay(&mut stream, &mut socket, stop, channel, &host, port);
            }
            command => bail!("unsupported FDR connection command {command:#x}"),
        }
    }
    Ok(())
}

/// Proxy bytes both ways until either side closes or the session stops.
fn relay<S: Read + Write>(
    stream: &mut MuxStream,
    socket: &mut S,
    stop: &AtomicBool,
    channel: u16,
    host: &str,
    port: u16,
) -> Result<()> {
    let mut buffer = vec![0; RELAY_BUFFER];
    let started = Instant::now();
    let mut from_mac = 0u64;
    let mut from_upstream = 0u64;
    let result = (|| -> Result<&str> {
        while !stop.load(Ordering::Relaxed) {
            match stream.read(&mut buffer) {
                Ok(0) => return Ok("EOF from Mac"),
                Ok(n) => {
                    crate::logging::bytes(
                        "fdr:proxy",
                        format_args!("#{channel} {host}:{port} TX offset={from_mac}"),
                        &buffer[..n],
                    );
                    from_mac += n as u64;
                    socket
                        .write_all(&buffer[..n])
                        .context("writing FDR payload to proxy/Apple")?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(error) => return Err(error).context("reading FDR payload from Mac"),
            }
            match socket.read(&mut buffer) {
                Ok(0) => return Ok("EOF from proxy/Apple"),
                Ok(n) => {
                    crate::logging::bytes(
                        "fdr:proxy",
                        format_args!("#{channel} {host}:{port} RX offset={from_upstream}"),
                        &buffer[..n],
                    );
                    from_upstream += n as u64;
                    stream
                        .write_all(&buffer[..n])
                        .context("writing FDR payload to Mac")?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => {
                    return Err(error).context("reading FDR payload from proxy/Apple");
                }
            }
        }
        Ok("FDR stopped")
    })();
    let reason = match &result {
        Ok(reason) => (*reason).to_owned(),
        Err(error) => format!("{error:#}"),
    };
    crate::log!(
        Debug,
        "fdr:proxy",
        "{host}:{port}: {reason}; TX={from_mac} B, RX={from_upstream} B; {:.3} s",
        started.elapsed().as_secs_f64()
    );
    result.map(|_| ())
}
