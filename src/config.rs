use std::path::PathBuf;
use std::time::Duration;

use structopt::StructOpt;

// constants
pub const SEMAPHORE_LIMIT: usize = 500;
pub const LOGGING_INTERVAL: usize = 5;
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(10);
pub const DB_PATH: &str = "./url_checker.db";

#[derive(Default, Debug, StructOpt)]
#[structopt(
    name = "domain_status",
    about = "Checks a list of URLs for their status and redirection."
)]
pub struct Opt {
    /// File to read
    #[structopt(parse(from_os_str))]
    pub file: PathBuf,

    /// Error rate threshold
    #[structopt(long, default_value = "60.0")]
    pub error_rate: f64,
}
