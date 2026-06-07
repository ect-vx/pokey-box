use crate::analyzers::clamav::ClamAvAnalyzer;
use crate::analyzers::malwarebazaar::MalwareBazaarAnalyzer;
use crate::analyzers::otx::OtxAnalyzer;
use crate::analyzers::safe_browsing::SafeBrowsingAnalyzer;
use crate::analyzers::urlhaus::UrlhausAnalyzer;
use crate::analyzers::virustotal::VirusTotalAnalyzer;
use crate::analyzers::yara::YaraAnalyzer;
use crate::analyzers::Analyze;
use crate::cli::{redis_client::RedisClient, Config};
use crate::db::Database;
use crate::models::{AnalyzerResult, Artifact, ThreatLevel, Verdict};
use anyhow::Result;
use futures::future::join_all;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct Engine {
    config: Config,
    db: Database,
    analyzers: Vec<Arc<dyn Analyze>>,
}

impl Engine {
    pub async fn new(config: Config) -> Result<Self> {
        let db = Database::connect(&config.database_url).await?;
        db.migrate().await?;

        let analyzers = build_analyzers(&config);
        info!(count = analyzers.len(), "Analyzers loaded");

        Ok(Self { config, db, analyzers })
    }

    /// Основная точка входа: UUID → Redis → артефакты → вердикты → PostgreSQL
    pub async fn run(
        &self,
        job_uuid: Uuid,
        concurrency: usize,
        timeout_secs: u64,
        verbose: bool,
    ) -> Result<Vec<Verdict>> {
        // 1. Забираем артефакты из Redis
        let mut redis = RedisClient::connect(&self.config.redis_url).await?;
        let artifacts = redis.fetch_artifacts(job_uuid).await?;

        if artifacts.is_empty() {
            warn!(%job_uuid, "no artifacts found");
            return Ok(vec![]);
        }

        info!(%job_uuid, count = artifacts.len(), "Starting analysis");

        // 2. Каждый артефакт анализируем параллельно
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut artifact_tasks = vec![];

        for artifact in artifacts {
            let analyzers = self.analyzers.clone();
            let sem = semaphore.clone();
            let db = self.db.clone();

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                analyze_artifact(job_uuid, artifact, analyzers, timeout_secs, verbose, db).await
            });

            artifact_tasks.push(task);
        }

        let results: Vec<Verdict> = join_all(artifact_tasks)
            .await
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        info!(
            %job_uuid,
            verdicts = results.len(),
            malicious = results.iter().filter(|v| v.threat_level == ThreatLevel::Malicious).count(),
            suspicious = results.iter().filter(|v| v.threat_level == ThreatLevel::Suspicious).count(),
            "Analysis complete"
        );

        Ok(results)
    }
}

/// Прогоняет один артефакт по всем анализаторам одновременно
async fn analyze_artifact(
    job_uuid: Uuid,
    artifact: Artifact,
    analyzers: Vec<Arc<dyn Analyze>>,
    timeout_secs: u64,
    verbose: bool,
    db: Database,
) -> Option<Verdict> {
    info!(artifact_id = %artifact.id, kind = %artifact.kind, "Analyzing artifact");

    // Все анализаторы запускаются параллельно
    let analyzer_futures: Vec<_> = analyzers
        .iter()
        .map(|a| {
            let artifact = artifact.clone();
            let analyzer = Arc::clone(a);
            async move {
                let name = analyzer.name();
                match timeout(Duration::from_secs(timeout_secs), analyzer.analyze(&artifact)).await {
                    Ok(result) => result,
                    Err(_) => AnalyzerResult {
                        analyzer: name.to_string(),
                        threat_level: ThreatLevel::Error,
                        score: None,
                        detections: vec![],
                        raw: serde_json::Value::Null,
                        error: Some(format!("timeout after {timeout_secs}s")),
                    },
                }
            }
        })
        .collect();

    let results: Vec<AnalyzerResult> = join_all(analyzer_futures).await;

    if verbose {
        for r in &results {
            let level = &r.threat_level;
            let name = &r.analyzer;
            let det = r.detections.join(", ");
            info!(?level, analyzer = name, detections = det, "  → result");
        }
    }

    let verdict = Verdict::build(job_uuid, &artifact, results);

    // Сохраняем в PostgreSQL
    if let Err(e) = db.upsert_verdict(&verdict).await {
        error!(artifact_id = %artifact.id, "Failed to save verdict: {e}");
    } else {
        info!(
            artifact_id = %artifact.id,
            level = %verdict.threat_level,
            score = verdict.total_score,
            "Verdict saved"
        );
    }

    Some(verdict)
}

fn build_analyzers(cfg: &Config) -> Vec<Arc<dyn Analyze>> {
    let mut analyzers: Vec<Arc<dyn Analyze>> = vec![];

    // VirusTotal (требует ключ)
    if let Some(key) = &cfg.virustotal_api_key {
        analyzers.push(Arc::new(VirusTotalAnalyzer::new(key.clone())));
        info!("✓ VirusTotal");
    } else {
        warn!("✗ VirusTotal — VIRUSTOTAL_API_KEY not set");
    }

    // OTX AlienVault (требует ключ)
    if let Some(key) = &cfg.otx_api_key {
        analyzers.push(Arc::new(OtxAnalyzer::new(key.clone())));
        info!("✓ OTX AlienVault");
    } else {
        warn!("✗ OTX AlienVault — OTX_API_KEY not set");
    }

    // Google Safe Browsing (требует ключ)
    if let Some(key) = &cfg.safe_browsing_api_key {
        analyzers.push(Arc::new(SafeBrowsingAnalyzer::new(key.clone())));
        info!("✓ Google Safe Browsing");
    } else {
        warn!("✗ Safe Browsing — SAFE_BROWSING_API_KEY not set");
    }

    // URLhaus — без ключа
    analyzers.push(Arc::new(UrlhausAnalyzer::new()));
    info!("✓ URLhaus");

    // MalwareBazaar — без ключа
    analyzers.push(Arc::new(MalwareBazaarAnalyzer::new()));
    info!("✓ MalwareBazaar");

    // ClamAV — через unix socket
    analyzers.push(Arc::new(ClamAvAnalyzer::new(&cfg.clamav_socket)));
    info!("✓ ClamAV");

    // YARA — по директории с правилами
    analyzers.push(Arc::new(YaraAnalyzer::new(&cfg.yara_rules_dir)));
    info!("✓ YARA");

    analyzers
}
