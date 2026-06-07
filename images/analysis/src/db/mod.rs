use crate::models::{Verdict, VerdictRow};
use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tracing::info;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(r#"CREATE TABLE IF NOT EXISTS verdicts (
            id               UUID        PRIMARY KEY,
            job_uuid         UUID        NOT NULL,
            artifact_id      TEXT        NOT NULL,
            artifact_kind    TEXT        NOT NULL,
            artifact_value   TEXT        NOT NULL,
            sha256           TEXT,
            threat_level     TEXT        NOT NULL,
            total_score      REAL        NOT NULL DEFAULT 0.0,
            analyzer_results JSONB       NOT NULL DEFAULT '[]',
            summary          TEXT        NOT NULL,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )"#).execute(&self.pool).await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS verdicts_job_uuid_idx ON verdicts (job_uuid)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS verdicts_threat_level_idx ON verdicts (threat_level)")
            .execute(&self.pool).await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS verdicts_created_at_idx ON verdicts (created_at DESC)")
            .execute(&self.pool).await?;

        info!("Database schema ready");
        Ok(())
    }

    pub async fn upsert_verdict(&self, v: &Verdict) -> Result<()> {
        sqlx::query(r#"
            INSERT INTO verdicts
                (id, job_uuid, artifact_id, artifact_kind, artifact_value, sha256,
                 threat_level, total_score, analyzer_results, summary, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            ON CONFLICT (id) DO UPDATE SET
                threat_level     = EXCLUDED.threat_level,
                total_score      = EXCLUDED.total_score,
                analyzer_results = EXCLUDED.analyzer_results,
                summary          = EXCLUDED.summary
        "#)
        .bind(v.id)
        .bind(v.job_uuid)
        .bind(&v.artifact_id)
        .bind(&v.artifact_kind)
        .bind(&v.artifact_value)
        .bind(&v.sha256)
        .bind(v.threat_level.to_string())
        .bind(v.total_score)
        .bind(&v.analyzer_results)
        .bind(&v.summary)
        .bind(v.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_verdicts_for_job(&self, job_uuid: uuid::Uuid) -> Result<Vec<VerdictRow>> {
        let rows = sqlx::query(r#"
            SELECT id, job_uuid, artifact_id, artifact_kind, artifact_value,
                   sha256, threat_level, total_score, summary, created_at
            FROM verdicts WHERE job_uuid = $1 ORDER BY created_at
        "#)
        .bind(job_uuid)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| VerdictRow {
                id:             r.get("id"),
                job_uuid:       r.get("job_uuid"),
                artifact_id:    r.get("artifact_id"),
                artifact_kind:  r.get("artifact_kind"),
                artifact_value: r.get("artifact_value"),
                sha256:         r.get("sha256"),
                threat_level:   r.get("threat_level"),
                total_score:    r.get("total_score"),
                summary:        r.get("summary"),
                created_at:     r.get("created_at"),
            })
            .collect())
    }
}
