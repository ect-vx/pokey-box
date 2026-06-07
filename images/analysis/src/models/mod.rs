use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Тип артефакта
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    Url,
    File,
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactKind::Url => write!(f, "url"),
            ArtifactKind::File => write!(f, "file"),
        }
    }
}

/// Артефакт — ссылка или файл
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub kind: ArtifactKind,
    pub value: String,
    pub sha256: Option<String>,
}

/// Уровень угрозы
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum ThreatLevel {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

impl fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatLevel::Clean      => write!(f, "CLEAN"),
            ThreatLevel::Suspicious => write!(f, "SUSPICIOUS"),
            ThreatLevel::Malicious  => write!(f, "MALICIOUS"),
            ThreatLevel::Error      => write!(f, "ERROR"),
        }
    }
}

/// Результат одного анализатора
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerResult {
    pub analyzer: String,
    pub threat_level: ThreatLevel,
    pub score: Option<f32>,
    pub detections: Vec<String>,
    pub raw: serde_json::Value,
    pub error: Option<String>,
}

/// Итоговый вердикт по артефакту
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub id: Uuid,
    pub job_uuid: Uuid,
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_value: String,
    pub sha256: Option<String>,
    pub threat_level: ThreatLevel,
    pub total_score: f32,
    pub analyzer_results: serde_json::Value,
    pub summary: String,
    pub created_at: DateTime<Utc>,
}

impl Verdict {
    pub fn build(job_uuid: Uuid, artifact: &Artifact, results: Vec<AnalyzerResult>) -> Self {
        let threat_level = results
            .iter()
            .filter(|r| r.threat_level != ThreatLevel::Error)
            .map(|r| r.threat_level)
            .max()
            .unwrap_or(ThreatLevel::Clean);

        let scores: Vec<f32> = results.iter()
            .filter(|r| r.threat_level != ThreatLevel::Error && r.threat_level != ThreatLevel::Clean)
            .filter_map(|r| r.score)
            .collect();
        let total_score = if scores.is_empty() { 0.0 } else { scores.iter().sum::<f32>() / scores.len() as f32 };

        let all_detections: Vec<String> = results.iter()
            .flat_map(|r| r.detections.iter().map(|d| format!("[{}] {}", r.analyzer, d)))
            .collect();

        let errors: Vec<String> = results.iter()
            .filter_map(|r| r.error.as_ref().map(|e| format!("[{}] ERR: {}", r.analyzer, e)))
            .collect();

        let summary = format!(
            "artifact={} kind={} level={} score={:.2} detections=[{}] errors=[{}]",
            artifact.id, artifact.kind, threat_level, total_score,
            all_detections.join("; "), errors.join("; ")
        );

        Verdict {
            id: Uuid::new_v4(),
            job_uuid,
            artifact_id: artifact.id.clone(),
            artifact_kind: artifact.kind.to_string(),
            artifact_value: artifact.value.clone(),
            sha256: artifact.sha256.clone(),
            threat_level,
            total_score,
            analyzer_results: serde_json::to_value(&results).unwrap_or_default(),
            summary,
            created_at: Utc::now(),
        }
    }
}

/// Строка из БД (без тяжёлого JSONB поля)
pub struct VerdictRow {
    pub id: Uuid,
    pub job_uuid: Uuid,
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_value: String,
    pub sha256: Option<String>,
    pub threat_level: String,
    pub total_score: f32,
    pub summary: String,
    pub created_at: DateTime<Utc>,
}
