//! Loopback helpers shared by HTTP, TLS and proxy unit tests.
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
    pkcs8::EncodePrivateKey,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyIdMethod, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData,
};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read},
    net::{TcpListener, TcpStream},
    sync::{Arc, OnceLock},
    thread,
    time::{Duration, Instant},
};
use time::{Duration as Validity, OffsetDateTime};

struct Loopback {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

// Reuse the application's P-256 implementation for certificate signing.
struct CertificateKey {
    signing: SigningKey,
    public: p256::Sec1Point,
}

impl CertificateKey {
    fn generate() -> Result<Self, rcgen::Error> {
        let signing =
            SigningKey::try_generate().map_err(|_| rcgen::Error::KeyGenerationUnavailable)?;
        let public = signing.verifying_key().to_sec1_point(false);
        Ok(Self { signing, public })
    }
}

impl PublicKeyData for CertificateKey {
    fn der_bytes(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for CertificateKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: Signature = self
            .signing
            .try_sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// macOS refuses to trust TLS server certificates with an over-long validity
/// period, reporting them as "not standards compliant". The loopback identity
/// is therefore minted for the current run instead of being checked in with a
/// fixed lifetime that either expires or violates Apple's 398-day limit.
fn loopback() -> &'static Loopback {
    static LOOPBACK: OnceLock<Loopback> = OnceLock::new();
    LOOPBACK.get_or_init(|| generate_loopback().expect("generating a loopback TLS identity"))
}

fn generate_loopback() -> Result<Loopback, rcgen::Error> {
    let now = OffsetDateTime::now_utc();
    // One year stays below Apple's 398-day limit for TLS server certificates.
    let not_before = now - Validity::minutes(5);
    let not_after = now + Validity::days(365);

    let mut authority_params = CertificateParams::new(Vec::new())?;
    authority_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_params
        .distinguished_name
        .push(DnType::CommonName, "Zalivka loopback test root");
    authority_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    authority_params.not_before = not_before;
    authority_params.not_after = not_after;
    authority_params.serial_number = Some(1u64.into());
    let authority_key = CertificateKey::generate()?;
    authority_params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha256::digest(authority_key.der_bytes())[..20].to_vec());
    let authority = authority_params.self_signed(&authority_key)?;

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.is_ca = IsCa::ExplicitNoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.use_authority_key_identifier_extension = true;
    server_params.not_before = not_before;
    server_params.not_after = not_after;
    server_params.serial_number = Some(2u64.into());
    let server_key = CertificateKey::generate()?;
    server_params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha256::digest(server_key.der_bytes())[..20].to_vec());
    let server = server_params.signed_by(
        &server_key,
        &Issuer::from_params(&authority_params, &authority_key),
    )?;

    Ok(Loopback {
        root: authority.der().clone(),
        leaf: server.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            server_key
                .signing
                .to_pkcs8_der()
                .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?
                .as_bytes()
                .to_vec(),
        )),
    })
}

/// Trust anchor for [`localhost_leaf`]; it is signed by this certificate.
pub(crate) fn localhost_root() -> CertificateDer<'static> {
    loopback().root.clone()
}

/// Server certificate presented by [`tls_server_config`] and validated as
/// `localhost` or `127.0.0.1`.
pub(crate) fn localhost_leaf() -> CertificateDer<'static> {
    loopback().leaf.clone()
}

pub(crate) fn tls_server_config() -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![loopback().leaf.clone()], loopback().key.clone_key())
            .unwrap(),
    )
}

pub(crate) fn accept(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("local server accept failed: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

// Read only headers: a following HTTP body or tunneled bytes must remain unread.
pub(crate) fn read_header(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 65536);
    }
    String::from_utf8(bytes).unwrap()
}
