use crate::models::{AnalyzerResult, Artifact};
use async_trait::async_trait;

pub mod clamav;
pub mod malwarebazaar;
pub mod otx;
pub mod safe_browsing;
pub mod urlhaus;
pub mod virustotal;
pub mod yara;

#[async_trait]
pub trait Analyze: Send + Sync {
    fn name(&self) -> &'static str;
    async fn analyze(&self, artifact: &Artifact) -> AnalyzerResult;
}
