pub mod redis_client;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "sandbox-analyzer",
    about = "Sandbox artifact analyzer — checks URLs and files against multiple threat intel sources",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analyze all artifacts for a given job UUID
    Analyze {
        uuid: String,
        #[arg(short, long, default_value = "8")]
        concurrency: usize,
        #[arg(short, long, default_value = "60")]
        timeout: u64,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show all verdicts for a job UUID from PostgreSQL
    Results { uuid: String },
    /// Health check — ping Redis and PostgreSQL
    Health,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub redis_url: String,
    pub database_url: String,
    pub virustotal_api_key: Option<String>,
    pub otx_api_key: Option<String>,
    pub safe_browsing_api_key: Option<String>,
    pub clamav_socket: String,
    pub yara_rules_dir: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        Config {
            redis_url:              std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".into()),
            database_url:          std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:postgres@postgres:5432/sandbox".into()),
            virustotal_api_key:    std::env::var("VIRUSTOTAL_API_KEY").ok(),
            otx_api_key:           std::env::var("OTX_API_KEY").ok(),
            safe_browsing_api_key: std::env::var("SAFE_BROWSING_API_KEY").ok(),
            clamav_socket:         std::env::var("CLAMAV_SOCKET").unwrap_or_else(|_| "/var/run/clamav/clamd.ctl".into()),
            yara_rules_dir:        std::env::var("YARA_RULES_DIR").unwrap_or_else(|_| "/app/yara-rules".into()),
        }
    }
}
