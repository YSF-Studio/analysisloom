//! Windows Event Log (.evtx) parser — security timeline events.

use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxEvent {
    pub event_id: u32,
    pub timestamp: String,
    pub channel: String,
    pub provider: String,
    pub level: String,
    pub message: String,
    pub record_id: u64,
    pub forensic_relevance: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxScanResult {
    pub log_path: String,
    pub events: Vec<EvtxEvent>,
    pub records_parsed: usize,
    pub channel: String,
}

const FORENSIC_EVENTS: &[(u32, &str, &str)] = &[
    (4624, "Successful Logon", "high"),
    (4625, "Failed Logon", "high"),
    (4688, "Process Creation", "medium"),
    (4104, "PowerShell Script Block", "high"),
    (7045, "Service Installed", "medium"),
    (4698, "Scheduled Task Created", "medium"),
    (4699, "Scheduled Task Deleted", "medium"),
    (1102, "Audit Log Cleared", "critical"),
];

pub fn parse_evtx_file(path: &str) -> Result<EvtxScanResult, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read EVTX: {e}"))?;
    if data.len() < 8 || &data[0..4] != b"ElfF" {
        return Err("Not a Windows Event Log (.evtx) — missing ElfFile header".into());
    }

    let mut events = parse_xml_fallback(&data);
    if events.is_empty() {
        events = parse_with_evtx_crate(path).unwrap_or_default();
    }

    let channel = events
        .first()
        .map(|e| e.channel.clone())
        .unwrap_or_else(|| "Security".into());

    Ok(EvtxScanResult {
        log_path: path.into(),
        records_parsed: events.len(),
        events,
        channel,
    })
}

pub fn scan_evtx_directory(dir: &str) -> Result<Vec<EvtxScanResult>, String> {
    let mut results = vec![];
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext == "evtx" {
                if let Ok(r) = parse_evtx_file(path.to_string_lossy().as_ref()) {
                    results.push(r);
                }
            }
        }
    }
    Ok(results)
}

fn parse_with_evtx_crate(path: &str) -> Result<Vec<EvtxEvent>, String> {
    let mut parser =
        evtx::EvtxParser::from_path(path).map_err(|e| format!("EVTX parse error: {e}"))?;
    let mut events = vec![];

    for record in parser.records_json_value().take(2000) {
        let record = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let json = record.data;
        let event_id = json
            .get("Event")
            .and_then(|e| e.get("System"))
            .and_then(|s| s.get("EventID"))
            .and_then(|id| id.as_u64().or_else(|| id.as_str()?.parse().ok()))
            .unwrap_or(0) as u32;

        if !is_forensic_event(event_id) {
            continue;
        }

        let system = json
            .get("Event")
            .and_then(|e| e.get("System"))
            .cloned()
            .unwrap_or(json.clone());

        let timestamp = system
            .get("TimeCreated")
            .and_then(|t| t.get("@SystemTime"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let channel = system
            .get("Channel")
            .and_then(|v| v.as_str())
            .unwrap_or("Security")
            .to_string();

        let provider = system
            .get("Provider")
            .and_then(|p| p.get("@Name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Microsoft-Windows-Security-Auditing")
            .to_string();

        let level = system
            .get("Level")
            .and_then(|v| v.as_u64())
            .map(|l| match l {
                1 => "Critical",
                2 => "Error",
                3 => "Warning",
                4 => "Info",
                _ => "Info",
            })
            .unwrap_or("Info")
            .to_string();

        let record_id = system
            .get("EventRecordID")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let message = extract_event_message(&json, event_id);

        events.push(EvtxEvent {
            event_id,
            timestamp,
            channel,
            provider,
            level,
            message,
            record_id,
            forensic_relevance: relevance_for(event_id).into(),
        });

        if events.len() >= 500 {
            break;
        }
    }

    Ok(events)
}

fn parse_xml_fallback(data: &[u8]) -> Vec<EvtxEvent> {
    let text = String::from_utf8_lossy(data);
    let id_re = Regex::new(r"(?i)<EventID[^>]*>(\d+)</EventID>").ok();
    let time_re = Regex::new(r#"(?i)SystemTime="([^"]+)""#).ok();
    let mut events = vec![];

    if let Some(re) = id_re {
        for cap in re.captures_iter(&text) {
            let event_id: u32 = cap
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            if !is_forensic_event(event_id) {
                continue;
            }
            let timestamp = time_re
                .as_ref()
                .and_then(|r| {
                    r.captures(&text)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                })
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

            events.push(EvtxEvent {
                event_id,
                timestamp,
                channel: "Security".into(),
                provider: "Microsoft-Windows-Security-Auditing".into(),
                level: "Info".into(),
                message: format!("Event ID {event_id}"),
                record_id: events.len() as u64,
                forensic_relevance: relevance_for(event_id).into(),
            });
            if events.len() >= 100 {
                break;
            }
        }
    }
    events
}

fn is_forensic_event(id: u32) -> bool {
    FORENSIC_EVENTS.iter().any(|(eid, _, _)| *eid == id)
}

fn relevance_for(id: u32) -> &'static str {
    FORENSIC_EVENTS
        .iter()
        .find(|(eid, _, _)| *eid == id)
        .map(|(_, label, _)| *label)
        .unwrap_or("Windows Event")
}

fn extract_event_message(json: &serde_json::Value, event_id: u32) -> String {
    if let Some(data) = json.get("Event").and_then(|e| e.get("EventData")) {
        if let Some(fields) = data.get("Data").and_then(|d| d.as_array()) {
            let parts: Vec<String> = fields
                .iter()
                .filter_map(|f| f.as_str().map(str::to_string))
                .take(4)
                .collect();
            if !parts.is_empty() {
                return parts.join(" | ");
            }
        }
    }
    relevance_for(event_id).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_evtx() {
        let path = std::env::temp_dir().join("not_evtx.bin");
        std::fs::write(&path, b"not an evtx file")
            .unwrap_or_else(|e| panic!("write evtx fixture: {e}"));
        let err = parse_evtx_file(path.to_string_lossy().as_ref()).unwrap_err();
        assert!(err.contains("ElfFile") || err.contains("EVTX"));
        let _ = std::fs::remove_file(path);
    }
}
