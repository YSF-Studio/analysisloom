//! Unified Super Timeline — multi-source event correlation.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuperTimelineEvent {
    pub timestamp: String,
    pub source: String,
    pub category: String,
    pub file_path: String,
    pub event_type: String,
    pub severity: String,
    pub correlation_id: String,
}

pub fn build_super_timeline(case_id: &str) -> Result<Vec<SuperTimelineEvent>, String> {
    let db = crate::db::conn();
    let mut events = vec![];

    let mut stmt = db
        .prepare(
            "SELECT timestamp, source, file_path, event_type FROM timeline_events WHERE case_id = ?1 ORDER BY timestamp ASC",
        )
        .map_err(|e| e.to_string())?;
    for row in stmt
        .query_map([case_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let (ts, source, path, etype) = row;
        let category = categorize_source(&source);
        events.push(SuperTimelineEvent {
            timestamp: ts,
            source: source.clone(),
            category,
            file_path: path,
            event_type: etype,
            severity: severity_for_event(&source),
            correlation_id: format!("{case_id}-{source}"),
        });
    }

    let mut fstmt = db
        .prepare("SELECT description, file_path, severity, created_at FROM findings WHERE case_id = ?1")
        .map_err(|e| e.to_string())?;
    for row in fstmt
        .query_map([case_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .flatten()
    {
        events.push(SuperTimelineEvent {
            timestamp: row.3.unwrap_or_else(|| chrono::Utc::now().to_rfc3339()),
            source: "Findings".into(),
            category: "evidence".into(),
            file_path: row.1,
            event_type: row.0,
            severity: row.2,
            correlation_id: format!("{case_id}-findings"),
        });
    }

    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(events)
}

fn categorize_source(source: &str) -> String {
    match source.to_uppercase().as_str() {
        s if s.contains("NTFS") || s.contains("MFT") => "filesystem",
        s if s.contains("REGISTRY") => "registry",
        s if s.contains("BROWSER") => "browser",
        s if s.contains("MEMORY") || s.contains("VOLATILITY") => "memory",
        s if s.contains("ENCRYPT") => "encryption",
        s if s.contains("CARV") => "carving",
        s if s.contains("YARA") => "malware",
        s if s.contains("ANTI") => "antiforensics",
        _ => "general",
    }
    .into()
}

fn severity_for_event(source: &str) -> String {
    match source.to_uppercase().as_str() {
        s if s.contains("YARA") || s.contains("ANTI") => "high",
        s if s.contains("ENCRYPT") => "medium",
        _ => "info",
    }
    .into()
}
