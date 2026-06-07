use crate::analyzers::Analyze;
use crate::models::{AnalyzerResult, Artifact, ArtifactKind, ThreatLevel};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, warn};

pub struct VirusTotalAnalyzer {
    client: Client,
    api_key: String,
}

impl VirusTotalAnalyzer {
    pub fn new(api_key: String) -> Self {
        Self {
            client: Client::new(),
            api_key,
        }
    }

    fn make_result(&self, level: ThreatLevel, score: Option<f32>, detections: Vec<String>, raw: Value, error: Option<String>) -> AnalyzerResult {
        AnalyzerResult {
            analyzer: self.name().to_string(),
            threat_level: level,
            score,
            detections,
            raw,
            error,
        }
    }

    async fn analyze_url(&self, url: &str) -> AnalyzerResult {
        // Шаг 1: отправить URL на сканирование
        let form = [("url", url)];
        let submit = self.client
            .post("https://www.virustotal.com/api/v3/urls")
            .header("x-apikey", &self.api_key)
            .form(&form)
            .send()
            .await;

        let submit_resp = match submit {
            Ok(r) => r,
            Err(e) => return self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some(e.to_string())),
        };

        let submit_json: Value = match submit_resp.json().await {
            Ok(j) => j,
            Err(e) => return self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some(e.to_string())),
        };

        // Извлекаем analysis id
        let analysis_id = match submit_json["data"]["id"].as_str() {
            Some(id) => id.to_string(),
            None => {
                return self.make_result(
                    ThreatLevel::Error, None, vec![], submit_json.clone(),
                    Some("no analysis id in response".into()),
                )
            }
        };

        self.poll_analysis(&analysis_id).await
    }

    async fn analyze_file_hash(&self, sha256: &str) -> AnalyzerResult {
        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let resp = self.client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let json: Value = r.json().await.unwrap_or_default();
                self.parse_stats(&json)
            }
            Err(e) => self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some(e.to_string())),
        }
    }

    async fn poll_analysis(&self, id: &str) -> AnalyzerResult {
        let url = format!("https://www.virustotal.com/api/v3/analyses/{id}");
        // Ждём до 3 попыток (публичный API медленный)
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
            }
            let resp = self.client
                .get(&url)
                .header("x-apikey", &self.api_key)
                .send()
                .await;

            let json: Value = match resp {
                Ok(r) => r.json().await.unwrap_or_default(),
                Err(e) => return self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some(e.to_string())),
            };

            let status = json["data"]["attributes"]["status"].as_str().unwrap_or("");
            debug!(analysis_id = id, status, attempt, "VT poll");

            if status == "completed" {
                return self.parse_stats(&json);
            }
        }
        self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some("VT analysis timed out".into()))
    }

    fn parse_stats(&self, json: &Value) -> AnalyzerResult {
        let stats = &json["data"]["attributes"]["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0);
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
        let harmless = stats["harmless"].as_u64().unwrap_or(0) + stats["undetected"].as_u64().unwrap_or(0);
        let total = malicious + suspicious + harmless;

        let score = if total > 0 { (malicious + suspicious) as f32 / total as f32 } else { 0.0 };

        let level = if malicious > 0 {
            ThreatLevel::Malicious
        } else if suspicious > 0 {
            ThreatLevel::Suspicious
        } else {
            ThreatLevel::Clean
        };

        // Собираем имена угроз из results
        let detections: Vec<String> = json["data"]["attributes"]["last_analysis_results"]
            .as_object()
            .map(|engines| {
                engines.values()
                    .filter(|v| {
                        let cat = v["category"].as_str().unwrap_or("");
                        cat == "malicious" || cat == "suspicious"
                    })
                    .filter_map(|v| v["result"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        self.make_result(level, Some(score), detections, json.clone(), None)
    }
}

#[async_trait]
impl Analyze for VirusTotalAnalyzer {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult {
        match artifact.kind {
            ArtifactKind::Url => self.analyze_url(&artifact.value).await,
            ArtifactKind::File => {
                if let Some(hash) = &artifact.sha256 {
                    self.analyze_file_hash(hash).await
                } else {
                    self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some("no sha256 for file".into()))
                }
            }
        }
    }
}
