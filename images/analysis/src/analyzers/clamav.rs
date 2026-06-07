use crate::analyzers::Analyze;
use crate::models::{AnalyzerResult, Artifact, ArtifactKind, ThreatLevel};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::warn;

/// ClamAV через Unix-сокет clamd (/var/run/clamav/clamd.ctl)
pub struct ClamAvAnalyzer {
    socket_path: PathBuf,
}

impl ClamAvAnalyzer {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self { socket_path: socket_path.into() }
    }

    fn make_result(&self, level: ThreatLevel, detections: Vec<String>, raw: Value, error: Option<String>) -> AnalyzerResult {
        let score = match level {
            ThreatLevel::Malicious => Some(1.0),
            _ => Some(0.0),
        };
        AnalyzerResult { analyzer: self.name().to_string(), threat_level: level, score, detections, raw, error }
    }

    /// Сканирует файл через SCAN команду clamd
    async fn scan_path(&self, path: &str) -> AnalyzerResult {
        let stream = match UnixStream::connect(&self.socket_path).await {
            Ok(s) => s,
            Err(e) => {
                warn!("ClamAV socket unavailable: {e}");
                return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(format!("socket error: {e}")));
            }
        };

        let (mut reader, mut writer) = tokio::io::split(stream);
        let cmd = format!("SCAN {path}\n");
        if let Err(e) = writer.write_all(cmd.as_bytes()).await {
            return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string()));
        }

        let mut response = String::new();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => response.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(e) => return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(e.to_string())),
            }
            if response.contains('\n') { break; }
        }

        let response = response.trim().to_string();
        let raw = json!({ "clamd_response": response });

        if response.ends_with("OK") {
            self.make_result(ThreatLevel::Clean, vec![], raw, None)
        } else if response.contains("FOUND") {
            // Формат: "/path/to/file: Virus.Name FOUND"
            let detection = response
                .split(':')
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_end_matches(" FOUND")
                .to_string();
            self.make_result(ThreatLevel::Malicious, vec![detection], raw, None)
        } else if response.contains("ERROR") {
            self.make_result(ThreatLevel::Error, vec![], raw, Some(response))
        } else {
            self.make_result(ThreatLevel::Clean, vec![], raw, None)
        }
    }

    /// Для URL — скачиваем во временный файл и сканируем
    async fn scan_url(&self, url: &str) -> AnalyzerResult {
        let tmp_path = format!("/tmp/clamav_url_{}", uuid::Uuid::new_v4());

        let download = reqwest::get(url).await;
        let bytes = match download {
            Ok(r) => r.bytes().await.unwrap_or_default(),
            Err(e) => return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(format!("download failed: {e}"))),
        };

        if let Err(e) = tokio::fs::write(&tmp_path, &bytes).await {
            return self.make_result(ThreatLevel::Error, vec![], Value::Null, Some(format!("write failed: {e}")));
        }

        let result = self.scan_path(&tmp_path).await;
        let _ = tokio::fs::remove_file(&tmp_path).await;
        result
    }
}

#[async_trait]
impl Analyze for ClamAvAnalyzer {
    fn name(&self) -> &'static str {
        "clamav"
    }

    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult {
        match artifact.kind {
            ArtifactKind::File => self.scan_path(&artifact.value).await,
            ArtifactKind::Url => self.scan_url(&artifact.value).await,
        }
    }
}
