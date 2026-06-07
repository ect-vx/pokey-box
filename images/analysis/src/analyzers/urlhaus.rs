use crate::analyzers::Analyze;
use crate::models::{AnalyzerResult, Artifact, ArtifactKind, ThreatLevel};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};

/// Проверяет URL и хэши через URLhaus API (бесплатно, без ключа)
pub struct UrlhausAnalyzer {
    client: Client,
}

impl UrlhausAnalyzer {
    pub fn new() -> Self {
        Self { client: Client::new() }
    }

    fn make_result(&self, level: ThreatLevel, detections: Vec<String>, raw: Value, error: Option<String>) -> AnalyzerResult {
        let score = match level {
            ThreatLevel::Malicious => Some(1.0),
            ThreatLevel::Suspicious => Some(0.5),
            _ => Some(0.0),
        };
        AnalyzerResult { analyzer: self.name().to_string(), threat_level: level, score, detections, raw, error }
    }

    async fn check_url(&self, url: &str) -> AnalyzerResult {
        let params = [("url", url)];
        let resp = self.client
            .post("https://urlhaus-api.abuse.ch/v1/url/")
            .form(&params)
            .send()
            .await;

        let json: Value = match resp {
            Ok(r) => r.json().await.unwrap_or_default(),
            Err(e) => return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())),
        };

        let query_status = json["query_status"].as_str().unwrap_or("no_results");

        match query_status {
            "is_host" | "is_url" => {
                let url_status = json["url_status"].as_str().unwrap_or("");
                let tags: Vec<String> = json["tags"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();

                let level = if url_status == "online" { ThreatLevel::Malicious } else { ThreatLevel::Suspicious };
                let mut detections = vec![format!("urlhaus_status={url_status}")];
                detections.extend(tags);
                self.make_result(level, detections, json, None)
            }
            _ => self.make_result(ThreatLevel::Clean, vec![], json, None),
        }
    }

    async fn check_hash(&self, sha256: &str) -> AnalyzerResult {
        let params = [("sha256_hash", sha256)];
        let resp = self.client
            .post("https://urlhaus-api.abuse.ch/v1/payload/")
            .form(&params)
            .send()
            .await;

        let json: Value = match resp {
            Ok(r) => r.json().await.unwrap_or_default(),
            Err(e) => return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())),
        };

        let query_status = json["query_status"].as_str().unwrap_or("no_results");
        if query_status == "ok" {
            let signature = json["signature"].as_str().unwrap_or("unknown").to_string();
            self.make_result(ThreatLevel::Malicious, vec![signature], json, None)
        } else {
            self.make_result(ThreatLevel::Clean, vec![], json, None)
        }
    }
}

#[async_trait]
impl Analyze for UrlhausAnalyzer {
    fn name(&self) -> &'static str {
        "urlhaus"
    }

    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult {
        match artifact.kind {
            ArtifactKind::Url => self.check_url(&artifact.value).await,
            ArtifactKind::File => {
                if let Some(hash) = &artifact.sha256 {
                    self.check_hash(hash).await
                } else {
                    self.make_result(ThreatLevel::Error, vec![], Value::Null, Some("no sha256".into()))
                }
            }
        }
    }
}
