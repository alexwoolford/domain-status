//! Generates shell completions and man page from the CLI structure.
//!
//! Keep the command tree in sync with `src/cli.rs` (`CliCommand`, `ScanCommand`, `ExportCommand`).

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use clap::Command;
use clap::ValueEnum;
use clap_complete::Shell;
use clap_mangen::Man;

const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

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
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let build_date = std::process::Command::new("date")
            .args(["+%Y-%m-%d"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        format!("{version_base} (debug {git_hash} {build_date})")
    };
    println!("cargo:rustc-env=DOMAIN_STATUS_VERSION={version_string}");
    println!("cargo:rerun-if-env-changed=PROFILE");
}

fn build_completion_manpage() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = domain_status_cli_command();

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

/// Builds the same CLI as `src/cli.rs` for codegen only. Keep in sync with `CliCommand`.
fn domain_status_cli_command() -> Command {
    Command::new("domain_status")
        .about("Domain intelligence scanner - scan URLs and export results.")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .subcommand(scan_command())
        .subcommand(export_command())
}

#[allow(clippy::cognitive_complexity)]
fn scan_command() -> Command {
    Command::new("scan")
        .about("Scan URLs and store results in SQLite database.")
        .arg(
            clap::arg!(<file> "File to read")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(--"log-level" <LEVEL> "Log level: error|warn|info|debug|trace")
                .default_value("info")
                .value_parser(["error", "warn", "info", "debug", "trace"]),
        )
        .arg(
            clap::arg!(--"log-format" <FORMAT> "Log format: plain|json")
                .default_value("plain")
                .value_parser(["plain", "json"]),
        )
        .arg(
            clap::arg!(--"db-path" <PATH> "Database path (SQLite file)")
                .default_value("./domain_status.db")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(--"max-concurrency" <N> "Maximum concurrent requests")
                .default_value("30")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            clap::arg!(--"timeout-seconds" <SECS> "Per-request timeout in seconds")
                .default_value("10")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            clap::arg!(--"user-agent" <UA> "HTTP User-Agent header value")
                .default_value(DEFAULT_USER_AGENT),
        )
        .arg(
            clap::arg!(--"rate-limit-rps" <RPS> "Initial requests per second (adaptive rate limiting always enabled)")
                .default_value("15")
                .value_parser(clap::value_parser!(u32)),
        )
        .arg(
            clap::arg!(--"max-per-domain" <N> "Maximum concurrent requests per registered domain")
                .default_value("5")
                .value_parser(clap::value_parser!(usize)),
        )
        .arg(
            clap::arg!(--"adaptive-error-threshold" <F> "Error rate threshold for adaptive rate limiting (0.0-1.0)")
                .default_value("0.2")
                .hide(true)
                .value_parser(clap::value_parser!(f64)),
        )
        .arg(clap::arg!(--fingerprints <URL_OR_PATH> "Fingerprints source URL or local path"))
        .arg(clap::arg!(--geoip <PATH_OR_URL> "GeoIP database path (MaxMind GeoLite2 .mmdb file) or download URL"))
        .arg(clap::arg!(--"status-port" <PORT> "HTTP status server port (optional, disabled by default)").value_parser(clap::value_parser!(u16)))
        .arg(clap::arg!(--"enable-whois" "Enable WHOIS/RDAP lookup for domain registration information"))
        .arg(
            clap::arg!(--"fail-on" <POLICY> "Exit code policy for handling failures")
                .default_value("never")
                .value_parser(["never", "any-failure", "pct>"]),
        )
        .arg(
            clap::arg!(--"fail-on-pct-threshold" <PCT> "Failure percentage threshold for --fail-on pct>X")
                .default_value("10")
                .value_parser(clap::value_parser!(u8).range(0..=100)),
        )
        .arg(
            clap::arg!(--"log-file" <PATH> "Log file path for detailed logging")
                .default_value("domain_status.log")
                .value_parser(clap::value_parser!(PathBuf)),
        )
}

#[allow(clippy::cognitive_complexity)]
fn export_command() -> Command {
    Command::new("export")
        .about("Export data from SQLite database to various formats.")
        .arg(
            clap::arg!(--"db-path" <PATH> "Database path (SQLite file)")
                .default_value("./domain_status.db")
                .value_parser(clap::value_parser!(PathBuf)),
        )
        .arg(
            clap::arg!(--format <FMT> "Export format: csv|jsonl|parquet")
                .default_value("csv")
                .value_parser(["csv", "jsonl", "parquet"]),
        )
        .arg(clap::arg!(--output <PATH> "Output file path"))
        .arg(clap::arg!(--"run-id" <ID> "Filter by run ID"))
        .arg(clap::arg!(--domain <DOMAIN> "Filter by domain (matches initial or final domain)"))
        .arg(clap::arg!(--status <CODE> "Filter by HTTP status code").value_parser(clap::value_parser!(u16)))
        .arg(clap::arg!(--since <TS> "Filter by timestamp (export records after this timestamp, in milliseconds since epoch)").value_parser(clap::value_parser!(i64)))
}
