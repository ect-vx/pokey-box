use crate::analyzers::Analyze;
use crate::models::{AnalyzerResult, Artifact, ArtifactKind, ThreatLevel};
use async_trait::async_trait;
use reqwest::Client;
use serde_json::{json, Value};

/// Google Safe Browsing v4 — бесплатно (10k req/day)
pub struct SafeBrowsingAnalyzer {
    client: Client,
    api_key: String,
}

impl SafeBrowsingAnalyzer {
    pub fn new(api_key: String) -> Self {
        Self { client: Client::new(), api_key }
    }

    fn make_result(&self, level: ThreatLevel, detections: Vec<String>, raw: Value, error: Option<String>) -> AnalyzerResult {
        let score = match level {
            ThreatLevel::Malicious => Some(1.0),
            ThreatLevel::Suspicious => Some(0.5),
            _ => Some(0.0),
        };
        AnalyzerResult { analyzer: self.name().to_string(), threat_level: level, score, detections, raw, error }
    }
}

#[async_trait]
impl Analyze for SafeBrowsingAnalyzer {
    fn name(&self) -> &'static str {
        "google_safe_browsing"
    }

    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult {
        if artifact.kind != ArtifactKind::Url {
            return self.make_result(ThreatLevel::Clean, vec![], Value::Null, None);
        }

        let body = json!({
            "client": { "clientId": "sandbox-analyzer", "clientVersion": "1.0" },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{ "url": artifact.value }]
            }
        });

        let url = format!(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}",
            self.api_key
        );

        let resp = self.client.post(&url).json(&body).send().await;

        let json: Value = match resp {
            Ok(r) => r.json().await.unwrap_or_default(),
            Err(e) => return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())),
        };

        let matches = json["matches"].as_array();
        match matches {
            Some(m) if !m.is_empty() => {
                let detections: Vec<String> = m
                    .iter()
                    .filter_map(|entry| entry["threatType"].as_str().map(String::from))
                    .collect();
                self.make_result(ThreatLevel::Malicious, detections, json, None)
            }
            _ => self.make_result(ThreatLevel::Clean, vec![], json, None),
        }
    }
}
