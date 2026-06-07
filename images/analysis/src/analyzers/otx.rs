use crate::analyzers::Analyze;
use crate::models::{AnalyzerResult, Artifact, ArtifactKind, ThreatLevel};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;
use url::Url;

/// OTX AlienVault — бесплатный threat intelligence
pub struct OtxAnalyzer {
    client: Client,
    api_key: String,
}

impl OtxAnalyzer {
    pub fn new(api_key: String) -> Self {
        Self { client: Client::new(), api_key }
    }

    fn make_result(&self, level: ThreatLevel, score: Option<f32>, detections: Vec<String>, raw: Value, error: Option<String>) -> AnalyzerResult {
        AnalyzerResult { analyzer: self.name().to_string(), threat_level: level, score, detections, raw, error }
    }

    async fn get(&self, url: &str) -> Result<Value, String> {
        self.client
            .get(url)
            .header("X-OTX-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json::<Value>()
            .await
            .map_err(|e| e.to_string())
    }

    async fn check_url(&self, raw_url: &str) -> AnalyzerResult {
        // Извлекаем хост для проверки домена
        let host = Url::parse(raw_url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| raw_url.to_string());

        let domain_url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{host}/general"
        );
        let url_url = format!(
            "https://otx.alienvault.com/api/v1/indicators/url/{}/general",
            urlencoding_simple(raw_url)
        );

        let (domain_res, url_res) = tokio::join!(self.get(&domain_url), self.get(&url_url));

        let mut pulses = 0u64;
        let mut detections = vec![];
        let mut combined = serde_json::json!({});

        if let Ok(j) = domain_res {
            pulses += j["pulse_info"]["count"].as_u64().unwrap_or(0);
            combined["domain"] = j;
        }
        if let Ok(j) = url_res {
            pulses += j["pulse_info"]["count"].as_u64().unwrap_or(0);
            if let Some(tags) = j["pulse_info"]["tags"].as_array() {
                detections.extend(tags.iter().filter_map(|t| t.as_str().map(String::from)));
            }
            combined["url"] = j;
        }

        let (level, score) = match pulses {
            0 => (ThreatLevel::Clean, 0.0f32),
            1..=9 => (ThreatLevel::Suspicious, 0.3),
            10..=49 => (ThreatLevel::Suspicious, 0.6),
            _ => (ThreatLevel::Malicious, 0.8),
        };

        if pulses > 0 {
            detections.push(format!("otx_pulses={pulses}"));
        }

        self.make_result(level, Some(score), detections, combined, None)
    }

    async fn check_hash(&self, sha256: &str) -> AnalyzerResult {
        let url = format!("https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general");
        match self.get(&url).await {
            Ok(json) => {
                let pulses = json["pulse_info"]["count"].as_u64().unwrap_or(0);
                let (level, score) = match pulses {
                    0 => (ThreatLevel::Clean, 0.0f32),
                    1..=9 => (ThreatLevel::Suspicious, 0.3),
                    10..=49 => (ThreatLevel::Suspicious, 0.6),
                    _ => (ThreatLevel::Malicious, 0.8),
                };
                let detections = if pulses > 0 { vec![format!("otx_pulses={pulses}")] } else { vec![] };
                self.make_result(level, Some(score), detections, json, None)
            }
            Err(e) => self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some(e)),
        }
    }
}

fn urlencoding_simple(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() || "._-~:/?#[]@!$&'()*+,;=".contains(c) { c.to_string() } else { format!("%{:02X}", c as u8) }).collect()
}

#[async_trait]
impl Analyze for OtxAnalyzer {
    fn name(&self) -> &'static str {
        "otx_alienvault"
    }

    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult {
        match artifact.kind {
            ArtifactKind::Url => self.check_url(&artifact.value).await,
            ArtifactKind::File => {
                if let Some(hash) = &artifact.sha256 {
                    self.check_hash(hash).await
                } else {
                    self.make_result(ThreatLevel::Error, None, vec![], Value::Null, Some("no sha256".into()))
                }
            }
        }
    }
}
