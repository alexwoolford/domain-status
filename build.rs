//! Generates shell completions and man page from the shared CLI definition.
//!
//! Single source of truth: `domain_status_cli::clap_command()` (same as used by the lib for parsing).

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use clap::ValueEnum;
use clap_complete::Shell;
use clap_mangen::Man;
use domain_status_cli::clap_command;

fn main() {
    emit_version_env();
    if env::var("DOCS_RS").is_ok() {
        return;
    }
    if let Err(e) = build_completion_manpage() {
        eprintln!("build script error: {e}");
        std::process::exit(1);
    }
}

/// For non-release builds, set `DOMAIN_STATUS_VERSION` to include git hash and build date.
/// Release builds keep the plain `CARGO_PKG_VERSION`.
fn emit_version_env() {
    let version_base = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let version_string = if env::var("PROFILE").as_deref() == Ok("release") {
        version_base
    } else {
        let git_hash = std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());
        let build_date = std::process::Command::new("date")
            .args(["+%Y-%m-%d"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());
        format!("{version_base} (debug {git_hash} {build_date})")
    };
    println!("cargo:rustc-env=DOMAIN_STATUS_VERSION={version_string}");
    println!("cargo:rerun-if-env-changed=PROFILE");
}

fn build_completion_manpage() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = clap_command(env!("CARGO_PKG_VERSION"));

    let gen_dir: PathBuf = env::var_os("DOMAIN_STATUS_GEN_DIR")
        .or_else(|| env::var_os("OUT_DIR"))
        .ok_or("OUT_DIR is unset")?
        .into();

    for shell in Shell::value_variants() {
        clap_complete::generate_to(*shell, &mut cmd.clone(), "domain_status", &gen_dir)?;
    }

    patch_bash_completion_for_paths(&gen_dir)?;

    let man_path = gen_dir.join("domain_status.1");
    let mut man_out = File::create(&man_path)?;
    let man = Man::new(cmd);
    man.render(&mut man_out)?;

    Ok(())
}

/// Patches the Bash completion script so path options (file, --db-path, --output, etc.) get
/// directory completion (e.g. `-o plusdirs`). Follows the same approach as feroxbuster.
fn patch_bash_completion_for_paths(
    gen_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let bash_path = gen_dir.join("domain_status.bash");
    if !bash_path.exists() {
        return Ok(());
    }
    let mut contents = String::new();
    let mut bash_file = OpenOptions::new().read(true).write(true).open(&bash_path)?;
    bash_file.read_to_string(&mut contents)?;
    let patched = contents.replace("default domain_status", "default -o plusdirs domain_status");
    if patched != contents {
        bash_file.rewind()?;
        bash_file.write_all(patched.as_bytes())?;
    }
    Ok(())
}
