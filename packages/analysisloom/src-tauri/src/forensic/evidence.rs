use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceId {
    pub prefix: String,
    pub date: String,
    pub sequence: String,
}

impl EvidenceId {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            date: Utc::now().format("%Y%m%d").to_string(),
            sequence: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        }
    }
}

impl std::fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}-{}", self.prefix, self.date, self.sequence)
    }
}
