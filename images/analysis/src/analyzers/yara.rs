use crate::analyzers::Analyze;
use crate::models::{AnalyzerResult, Artifact, ArtifactKind, ThreatLevel};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::warn;

/// YARA — сканирует файлы по набору правил из директории
pub struct YaraAnalyzer {
    rules_path: PathBuf,
}

impl YaraAnalyzer {
    pub fn new(rules_path: impl Into<PathBuf>) -> Self {
        Self { rules_path: rules_path.into() }
    }

    fn make_result(&self, level: ThreatLevel, detections: Vec<String>, raw: Value, error: Option<String>) -> AnalyzerResult {
        let score = match level {
            ThreatLevel::Malicious => Some(1.0),
            ThreatLevel::Suspicious => Some(0.5),
            _ => Some(0.0),
        };
        AnalyzerResult { analyzer: self.name().to_string(), threat_level: level, score, detections, raw, error }
    }

    /// Компилирует и применяет правила в отдельном блокирующем потоке
    async fn scan_bytes(&self, data: Vec<u8>, source_label: &str) -> AnalyzerResult {
        let rules_path = self.rules_path.clone();
        let label = source_label.to_string();

        tokio::task::spawn_blocking(move || {
            let compiler = match yara::Compiler::new() {
                Ok(c) => c,
                Err(e) => {
                    return (ThreatLevel::Error, vec![], json!({}), Some(format!("yara init: {e}")));
                }
            };

            // Загружаем все .yar файлы из директории
            let mut compiler = compiler;
if let Ok(entries) = std::fs::read_dir(&rules_path) {
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e == "yar").unwrap_or(false) {
            compiler = match compiler.add_rules_file(&path) {
                Ok(c) => c,
                Err(e) => {
                    warn!(?path, "YARA rule load failed: {e}");
                    return (ThreatLevel::Error, vec![], json!({}), Some(format!("yara rule load: {e}")));
                }
            };
        }
    }
}

            let rules = match compiler.compile_rules() {
                Ok(r) => r,
                Err(e) => return (ThreatLevel::Error, vec![], json!({}), Some(format!("yara compile: {e}"))),
            };

            let matches = match rules.scan_mem(&data, 30) {
                Ok(m) => m,
                Err(e) => return (ThreatLevel::Error, vec![], json!({}), Some(format!("yara scan: {e}"))),
            };

            if matches.is_empty() {
                return (ThreatLevel::Clean, vec![], json!({"matches": []}), None);
            }

            let detections: Vec<String> = matches.iter().map(|m| m.identifier.to_string()).collect();
            let raw = json!({ "source": label, "matches": detections });

            // Помечаем как SUSPICIOUS — финальная классификация за агрегатором
            (ThreatLevel::Suspicious, detections, raw, None)
        })
        .await
        .map(|(level, det, raw, err)| self.make_result(level, det, raw, err))
        .unwrap_or_else(|e| self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())))
    }
}

#[async_trait]
impl Analyze for YaraAnalyzer {
    fn name(&self) -> &'static str {
        "yara"
    }

    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult {
        match artifact.kind {
            ArtifactKind::File => {
                let data = match tokio::fs::read(&artifact.value).await {
                    Ok(d) => d,
                    Err(e) => return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())),
                };
                self.scan_bytes(data, &artifact.value).await
            }
            ArtifactKind::Url => {
                // Скачиваем и сканируем контент URL
                match reqwest::get(&artifact.value).await {
                    Ok(r) => {
                        let bytes = r.bytes().await.unwrap_or_default().to_vec();
                        self.scan_bytes(bytes, &artifact.value).await
                    }
                    Err(e) => self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())),
                }
            }
        }
    }
}
