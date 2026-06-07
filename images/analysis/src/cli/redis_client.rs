use crate::models::{Artifact, ArtifactKind};
use anyhow::{anyhow, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use tracing::debug;
use url::Url;
use uuid::Uuid;

pub struct RedisClient {
    conn: ConnectionManager,
}

impl RedisClient {
    pub async fn connect(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    /// Забирает строку артефактов для данного uuid.
    /// Ключ: `artifacts::{uuid}`, значение: `item1|item2|item3`
    pub async fn fetch_artifacts(&mut self, uuid: Uuid) -> Result<Vec<Artifact>> {
        let key = format!("artifacts::{uuid}");
        let raw: Option<String> = self.conn.get(&key).await?;

        let raw = raw.ok_or_else(|| anyhow!("key '{key}' not found in Redis"))?;
        debug!(key, raw, "fetched artifact string from Redis");

        let artifacts = raw
            .split('|')
            .filter(|s| !s.trim().is_empty())
            .enumerate()
            .map(|(i, s)| parse_artifact(i, s.trim()))
            .collect();

        Ok(artifacts)
    }
}

/// Определяем тип: если строка парсится как URL — это URL, иначе — путь к файлу
fn parse_artifact(index: usize, value: &str) -> Artifact {
    let is_url = Url::parse(value)
        .map(|u| u.scheme() == "http" || u.scheme() == "https" || u.scheme() == "ftp")
        .unwrap_or(false);

    let kind = if is_url { ArtifactKind::Url } else { ArtifactKind::File };

    // Для файлов считаем sha256 если файл существует
    let sha256 = if kind == ArtifactKind::File {
        compute_file_sha256(value)
    } else {
        None
    };

    Artifact {
        id: format!("{index}_{}", slug(value)),
        kind,
        value: value.to_string(),
        sha256,
    }
}

fn compute_file_sha256(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(hex::encode(hasher.finalize()))
}

fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .take(48)
        .collect()
}
