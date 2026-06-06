//! Linux endpoint artifacts — auditd, auth.log, bash history.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxEvent {
    pub event_type: String,
    pub timestamp: String,
    pub user: String,
    pub source: String,
    pub command: String,
    pub details: String,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinuxScanResult {
    pub events: Vec<LinuxEvent>,
    pub auth_events: usize,
    pub audit_events: usize,
    pub history_commands: usize,
    pub files_parsed: usize,
}

pub fn scan_linux_artifacts(root: &str) -> Result<LinuxScanResult, String> {
    let root = Path::new(root);
    if !root.exists() {
        return Err(format!("Path not found: {}", root.display()));
    }

    let mut events = vec![];
    let mut files = vec![];
    collect_linux_files(root, 0, 6, &mut files);

    let files_parsed = files.len();
    for path in &files {
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let lower = fname.to_lowercase();
        let parsed = if lower.contains("auth.log") || lower == "secure" {
            parse_auth_log(path)
        } else if lower.contains("audit.log") || lower.starts_with("audit") {
            parse_audit_log(path)
        } else if lower.contains("bash_history") || lower == ".bash_history" {
            parse_bash_history(path)
        } else {
            vec![]
        };
        events.extend(parsed);
    }

    let auth_events = events
        .iter()
        .filter(|e| e.event_type.starts_with("auth"))
        .count();
    let audit_events = events
        .iter()
        .filter(|e| e.event_type.starts_with("audit"))
        .count();
    let history_commands = events
        .iter()
        .filter(|e| e.event_type == "bash_history")
        .count();

    Ok(LinuxScanResult {
        auth_events,
        audit_events,
        history_commands,
        files_parsed,
        events,
    })
}

fn collect_linux_files(dir: &Path, depth: u8, max: u8, out: &mut Vec<std::path::PathBuf>) {
    if depth > max {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                let lower = name.to_lowercase();
                if lower.contains("auth.log")
                    || lower == "secure"
                    || lower.contains("audit")
                    || lower.contains("bash_history")
                {
                    out.push(path);
                }
            }
        } else if path.is_dir() {
            collect_linux_files(&path, depth + 1, max, out);
        }
    }
}

pub fn parse_auth_log(path: &Path) -> Vec<LinuxEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let mut events = vec![];
    for line in content.lines().take(500) {
        let event_type =
            if line.contains("Accepted password") || line.contains("Accepted publickey") {
                "auth_success"
            } else if line.contains("Failed password") || line.contains("Invalid user") {
                "auth_failure"
            } else if line.contains("session opened") {
                "auth_session"
            } else {
                continue;
            };

        let timestamp = line.chars().take(15).collect::<String>();
        let user = extract_field(line, "for ")
            .or_else(|| extract_field(line, "user "))
            .unwrap_or_else(|| "—".into());
        let source = extract_field(line, "from ").unwrap_or_else(|| "—".into());

        events.push(LinuxEvent {
            event_type: event_type.into(),
            timestamp,
            user,
            source,
            command: String::new(),
            details: line.chars().take(200).collect(),
            source_file: path.to_string_lossy().into(),
        });
    }
    events
}

pub fn parse_audit_log(path: &Path) -> Vec<LinuxEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let mut events = vec![];
    for line in content.lines().take(500) {
        if !line.contains("type=") {
            continue;
        }
        let event_type = extract_audit_type(line);
        let timestamp = line
            .split("msg=audit(")
            .nth(1)
            .and_then(|s| s.split(':').next())
            .unwrap_or("—")
            .to_string();
        let user = extract_audit_field(line, "acct=").or_else(|| extract_audit_field(line, "uid="));
        let exe = extract_audit_field(line, "exe=").unwrap_or_default();
        let cmd = extract_audit_field(line, "cmd=").unwrap_or_default();

        events.push(LinuxEvent {
            event_type: format!("audit_{event_type}"),
            timestamp,
            user: user.unwrap_or_else(|| "—".into()),
            source: exe,
            command: cmd,
            details: line.chars().take(200).collect(),
            source_file: path.to_string_lossy().into(),
        });
    }
    events
}

pub fn parse_bash_history(path: &Path) -> Vec<LinuxEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![];
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(200)
        .enumerate()
        .map(|(i, line)| LinuxEvent {
            event_type: "bash_history".into(),
            timestamp: format!("#{i}"),
            user: "—".into(),
            source: String::new(),
            command: line.trim().chars().take(300).collect(),
            details: "Shell command history entry".into(),
            source_file: path.to_string_lossy().into(),
        })
        .collect()
}

fn extract_field(line: &str, prefix: &str) -> Option<String> {
    let idx = line.find(prefix)?;
    let rest = &line[idx + prefix.len()..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ':' || c == ';')
        .unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

fn extract_audit_type(line: &str) -> String {
    line.split("type=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or("UNKNOWN")
        .trim_matches('"')
        .trim_end_matches(')')
        .to_string()
}

fn extract_audit_field(line: &str, key: &str) -> Option<String> {
    let idx = line.find(key)?;
    let rest = &line[idx + key.len()..];
    let val = if rest.starts_with('"') {
        rest.trim_start_matches('"').split('"').next()?.to_string()
    } else {
        rest.split_whitespace()
            .next()?
            .trim_matches('"')
            .to_string()
    };
    Some(val)
}
