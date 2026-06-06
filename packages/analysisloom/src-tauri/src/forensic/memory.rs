//! Volatility 3 JSON output bridge for memory dump analysis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryProcess {
    pub pid: u64,
    pub name: String,
    pub ppid: u64,
    pub cmdline: String,
    pub create_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryNetwork {
    pub pid: u64,
    pub protocol: String,
    pub local_addr: String,
    pub foreign_addr: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryAnalysisResult {
    pub plugin: String,
    pub processes: Vec<MemoryProcess>,
    pub networks: Vec<MemoryNetwork>,
    pub raw_entries: usize,
    pub source_file: String,
}

pub fn parse_volatility_json(path: &str) -> Result<MemoryAnalysisResult, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_volatility_json_str(&content, path)
}

pub fn parse_volatility_json_str(content: &str, source: &str) -> Result<MemoryAnalysisResult, String> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid Volatility JSON: {e}"))?;

    let mut processes = vec![];
    let mut networks = vec![];
    let mut raw_entries = 0usize;
    let mut plugin = "unknown".to_string();

    if let Some(rows) = value.as_array() {
        raw_entries = rows.len();
        for row in rows {
            if let Some(p) = parse_process_row(row) {
                processes.push(p);
            }
            if let Some(n) = parse_network_row(row) {
                networks.push(n);
            }
        }
        plugin = "volatility3.json".into();
    } else if let Some(obj) = value.as_object() {
        for (key, rows) in obj {
            plugin = key.clone();
            if let Some(arr) = rows.as_array() {
                raw_entries += arr.len();
                for row in arr {
                    if let Some(p) = parse_process_row(row) {
                        processes.push(p);
                    }
                    if let Some(n) = parse_network_row(row) {
                        networks.push(n);
                    }
                }
            }
        }
    }

    Ok(MemoryAnalysisResult {
        plugin,
        processes,
        networks,
        raw_entries,
        source_file: source.into(),
    })
}

fn parse_process_row(row: &serde_json::Value) -> Option<MemoryProcess> {
    let pid = row.get("PID").or_else(|| row.get("pid"))?.as_u64()?;
    let name = row
        .get("ImageFileName")
        .or_else(|| row.get("Process"))
        .or_else(|| row.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let ppid = row
        .get("PPID")
        .or_else(|| row.get("ppid"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cmdline = row
        .get("CommandLine")
        .or_else(|| row.get("cmdline"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let create_time = row
        .get("CreateTime")
        .or_else(|| row.get("create_time"))
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".into());
    Some(MemoryProcess {
        pid,
        name,
        ppid,
        cmdline,
        create_time,
    })
}

fn parse_network_row(row: &serde_json::Value) -> Option<MemoryNetwork> {
    let foreign = row.get("ForeignAddr").or_else(|| row.get("foreign"))?;
    let local = row.get("LocalAddr").or_else(|| row.get("local"))?;
    Some(MemoryNetwork {
        pid: row.get("PID").or_else(|| row.get("pid")).and_then(|v| v.as_u64()).unwrap_or(0),
        protocol: row
            .get("Proto")
            .or_else(|| row.get("protocol"))
            .and_then(|v| v.as_str())
            .unwrap_or("TCP")
            .into(),
        local_addr: local.as_str().unwrap_or("").into(),
        foreign_addr: foreign.as_str().unwrap_or("").into(),
        state: row
            .get("State")
            .or_else(|| row.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
    })
}
