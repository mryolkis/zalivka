//! Embed build identity and the Windows icon before compiling the crate.
use std::{
    env,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

/// Paths whose changes must trigger a rebuild.
const INPUTS: [&str; 8] = [
    "build.rs",
    "Cargo.toml",
    "Cargo.lock",
    "src",
    "locales",
    "assets",
    "certs",
    "packaging",
];

fn main() {
    println!("cargo:rerun-if-env-changed=ZALIVKA_RELEASE_VERSION");
    let package = env::var("CARGO_PKG_VERSION").expect("package version");
    let release = env::var("ZALIVKA_RELEASE_VERSION").ok();
    if let Some(version) = &release {
        assert_eq!(version, &package, "release and package versions differ");
    }
    embed_windows_icon();
    println!("cargo:rustc-env=ZALIVKA_COMPILER={}", compiler_version());
    for (name, key) in [("ZALIVKA_TARGET", "TARGET"), ("ZALIVKA_PROFILE", "PROFILE")] {
        println!("cargo:rustc-env={name}={}", env::var(key).expect(key));
    }
    for input in INPUTS {
        println!("cargo:rerun-if-changed={input}");
    }
    watch_git_metadata();
    let built_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("build time before Unix epoch")
        .as_nanos();
    let revision = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&dirty_arguments()).is_some_and(|status| !status.is_empty());
    println!("cargo:rustc-env=ZALIVKA_BUILT_AT={built_at}");
    let version = release.unwrap_or_else(|| {
        let suffix = format!("{revision}{}.{built_at}", if dirty { ".dirty" } else { "" });
        let separator = if package.contains('+') { '.' } else { '+' };
        format!("{package}{separator}{suffix}")
    });
    println!("cargo:rustc-env=ZALIVKA_VERSION={version}");
}

#[cfg(feature = "gui")]
fn embed_windows_icon() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/logo.ico")
            .compile()
            .expect("embedding the Windows application icon");
    }
}

#[cfg(not(feature = "gui"))]
fn embed_windows_icon() {}

fn compiler_version() -> String {
    let output = Command::new(env::var_os("RUSTC").expect("RUSTC"))
        .arg("--version")
        .output()
        .expect("reading compiler version");
    assert!(output.status.success(), "reading compiler version failed");
    String::from_utf8(output.stdout)
        .expect("UTF-8 compiler version")
        .trim()
        .to_owned()
}

fn git(arguments: &[&str]) -> Option<String> {
    let output = Command::new("git").args(arguments).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Source paths and HEAD cover edits, staging and commits. Merely refreshing
/// Git's stat cache must not rebuild the executable.
fn watch_git_metadata() {
    for arguments in [
        vec!["rev-parse", "--git-path", "HEAD"],
        vec!["rev-parse", "--git-path", "packed-refs"],
    ] {
        if let Some(path) = git(&arguments) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &reference])
    {
        println!("cargo:rerun-if-changed={path}");
    }
}

fn dirty_arguments() -> Vec<&'static str> {
    let mut arguments = vec!["status", "--porcelain", "--untracked-files=normal", "--"];
    arguments.extend(INPUTS);
    arguments
}
