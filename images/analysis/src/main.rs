mod analyzers;
mod cli;
mod db;
mod engine;
mod models;

use crate::cli::{Cli, Command, Config};
use crate::engine::Engine;
use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let config = Config::from_env();

    match cli.command {
        Command::Analyze { uuid, concurrency, timeout, verbose } => {
            let job_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| anyhow::anyhow!("Invalid UUID '{uuid}': {e}"))?;

            info!(%job_uuid, "Starting sandbox analysis");

            let engine = Engine::new(config).await?;
            let verdicts = engine.run(job_uuid, concurrency, timeout, verbose).await?;

            println!("\n═══════════════════════════════════════════════════");
            println!("  Job: {job_uuid}");
            println!("  Artifacts analyzed: {}", verdicts.len());
            println!("═══════════════════════════════════════════════════");

            for v in &verdicts {
                let icon = match v.threat_level {
                    models::ThreatLevel::Malicious  => "🔴 MALICIOUS",
                    models::ThreatLevel::Suspicious => "🟡 SUSPICIOUS",
                    models::ThreatLevel::Clean      => "🟢 CLEAN",
                    models::ThreatLevel::Error      => "⚫ ERROR",
                };
                println!("  [{icon}] score={:.2}  {}", v.total_score, v.artifact_value);
                if verbose {
                    println!("    {}", v.summary);
                }
            }
            println!("═══════════════════════════════════════════════════\n");
        }

        Command::Results { uuid } => {
            let job_uuid = Uuid::parse_str(&uuid)
                .map_err(|e| anyhow::anyhow!("Invalid UUID '{uuid}': {e}"))?;
            let db = db::Database::connect(&config.database_url).await?;
            let rows = db.get_verdicts_for_job(job_uuid).await?;
            if rows.is_empty() {
                println!("No verdicts found for job {job_uuid}");
            } else {
                for r in &rows {
                    println!("[{}] {} | score={:.2}", r.threat_level, r.artifact_value, r.total_score);
                    println!("  {}", r.summary);
                }
            }
        }

        Command::Health => {
            match cli::redis_client::RedisClient::connect(&config.redis_url).await {
                Ok(_) => println!("✓ Redis: OK"),
                Err(e) => eprintln!("✗ Redis: {e}"),
            }
            match db::Database::connect(&config.database_url).await {
                Ok(_) => println!("✓ PostgreSQL: OK"),
                Err(e) => eprintln!("✗ PostgreSQL: {e}"),
            }
        }
    }

    Ok(())
}
