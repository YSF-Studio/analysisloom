//! Email forensics — PST/OST mailbox header parsing and message extraction.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailMessage {
    pub subject: String,
    pub sender: String,
    pub recipients: String,
    pub sent_time: String,
    pub folder: String,
    pub body_preview: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailScanResult {
    pub file_path: String,
    pub mailbox_type: String,
    pub version: u32,
    pub encrypted: bool,
    pub message_count: usize,
    pub messages: Vec<EmailMessage>,
    pub folders: Vec<String>,
    pub details: String,
}

pub fn scan_email_directory(dir: &str) -> Result<Vec<EmailScanResult>, String> {
    let dir = Path::new(dir);
    if !dir.exists() {
        return Err(format!("Directory not found: {}", dir.display()));
    }
    let mut results = vec![];
    scan_dir(dir, 0, 4, &mut results);
    Ok(results)
}

fn scan_dir(dir: &Path, depth: u8, max: u8, out: &mut Vec<EmailScanResult>) {
    if depth > max {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let lower = ext.to_lowercase();
                if lower == "pst" || lower == "ost" {
                    if let Ok(r) = parse_mailbox(&path) {
                        out.push(r);
                    }
                }
            }
        } else if path.is_dir() {
            scan_dir(&path, depth + 1, max, out);
        }
    }
}

pub fn parse_mailbox(path: &Path) -> Result<EmailScanResult, String> {
    let data = std::fs::read(path).map_err(|e| format!("Read mailbox: {e}"))?;
    if data.len() < 0x200 {
        return Err("Mailbox file too small".into());
    }

    let Some(magic_bytes) = data.get(0..4) else {
        return Err("Mailbox file too small".into());
    };
    let magic = u32::from_le_bytes([magic_bytes[0], magic_bytes[1], magic_bytes[2], magic_bytes[3]]);
    let (mailbox_type, version) = match magic {
        0x4E444221 => (
            "PST (ANSI)".into(),
            u16::from_le_bytes(data.get(10..12).and_then(|s| s.try_into().ok()).unwrap_or([0; 2]))
                as u32,
        ),
        0x4D505349 => (
            "OST (Unicode)".into(),
            u16::from_le_bytes(data.get(10..12).and_then(|s| s.try_into().ok()).unwrap_or([0; 2]))
                as u32,
        ),
        0x21_42_44_4E => (
            "PST (Unicode)".into(),
            u16::from_le_bytes(data.get(10..12).and_then(|s| s.try_into().ok()).unwrap_or([0; 2]))
                as u32,
        ),
        _ => {
            if data.starts_with(b"!BDN") {
                ("PST".into(), 23)
            } else {
                return Err(format!("Unknown mailbox magic: 0x{magic:08X}"));
            }
        }
    };

    let encrypted = data.len() > 0x1A && data[0x1A] != 0;
    let messages = extract_messages(&data);
    let folders = extract_folders(&data);
    let message_count = messages.len();
    let folder_count = folders.len();

    Ok(EmailScanResult {
        file_path: path.to_string_lossy().into(),
        mailbox_type,
        version,
        encrypted,
        message_count,
        messages,
        folders,
        details: format!(
            "Parsed {message_count} message stubs, {folder_count} folders, encrypted={encrypted}"
        ),
    })
}

fn extract_messages(data: &[u8]) -> Vec<EmailMessage> {
    let mut messages = vec![];
    let markers: &[(&[u8], &str)] = &[
        (b"Subject:", "subject"),
        (b"From:", "from"),
        (b"To:", "to"),
        (b"Date:", "date"),
    ];

    let text = String::from_utf8_lossy(data);
    let lines: Vec<&str> = text.split('\0').filter(|l| l.len() > 4).collect();

    let mut current = EmailMessage {
        subject: String::new(),
        sender: String::new(),
        recipients: String::new(),
        sent_time: String::new(),
        folder: "Inbox".into(),
        body_preview: String::new(),
    };

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        for (marker, field) in markers {
            if let Some(rest) = trimmed.strip_prefix(std::str::from_utf8(marker).unwrap_or("")) {
                match *field {
                    "subject" => current.subject = rest.trim().chars().take(200).collect(),
                    "from" => current.sender = rest.trim().chars().take(120).collect(),
                    "to" => current.recipients = rest.trim().chars().take(200).collect(),
                    "date" => current.sent_time = rest.trim().chars().take(60).collect(),
                    _ => {}
                }
            }
        }
        if current.subject.is_empty()
            && (10..200).contains(&trimmed.len())
            && trimmed.contains('@')
            && trimmed.contains('.')
            && current.sender.is_empty()
        {
            current.sender = trimmed.chars().take(120).collect();
        }
        if !current.subject.is_empty() && !current.sender.is_empty() {
            current.body_preview = trimmed.chars().take(120).collect();
            messages.push(current.clone());
            current = EmailMessage {
                subject: String::new(),
                sender: String::new(),
                recipients: String::new(),
                sent_time: String::new(),
                folder: "Inbox".into(),
                body_preview: String::new(),
            };
            if messages.len() >= 50 {
                break;
            }
        }
    }

    if messages.is_empty() {
        for utf16_msg in scan_utf16_strings(data, 8) {
            messages.push(EmailMessage {
                subject: utf16_msg.chars().take(200).collect(),
                sender: "—".into(),
                recipients: "—".into(),
                sent_time: "—".into(),
                folder: "Recovered".into(),
                body_preview: String::new(),
            });
            if messages.len() >= 20 {
                break;
            }
        }
    }

    messages
}

fn extract_folders(data: &[u8]) -> Vec<String> {
    let mut folders = vec![];
    for name in [
        "Inbox",
        "Sent Items",
        "Deleted Items",
        "Drafts",
        "Outbox",
        "Calendar",
        "Contacts",
    ] {
        if data.windows(name.len()).any(|w| w == name.as_bytes()) {
            folders.push(name.into());
        }
    }
    for s in scan_utf16_strings(data, 4) {
        if (2..64).contains(&s.len())
            && !folders.contains(&s)
            && s.chars()
                .all(|c| c.is_alphanumeric() || c.is_whitespace() || c == '-' || c == '_')
        {
            folders.push(s);
        }
        if folders.len() >= 15 {
            break;
        }
    }
    if folders.is_empty() {
        folders.push("Root".into());
    }
    folders
}

fn scan_utf16_strings(data: &[u8], min_chars: usize) -> Vec<String> {
    let mut results = vec![];
    let mut i = 0usize;
    while i + 4 < data.len() {
        if (0x20..=0x7E).contains(&data[i]) && data[i + 1] == 0 {
            if let Some(s) = read_utf16le(data, i) {
                if s.len() >= min_chars
                    && s.chars().any(|c| c.is_alphabetic())
                    && !results.contains(&s)
                {
                    results.push(s);
                }
            }
        }
        i += 1;
    }
    results
}

fn read_utf16le(data: &[u8], start: usize) -> Option<String> {
    let mut chars = vec![];
    let mut i = start;
    while i + 1 < data.len() && chars.len() < 128 {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        if ch == 0 {
            break;
        }
        if ch < 0x20 || (ch > 0x7E && ch < 0xA0) {
            if chars.len() < 4 {
                return None;
            }
            break;
        }
        chars.push(ch);
        i += 2;
    }
    if chars.len() < 4 {
        None
    } else {
        Some(String::from_utf16_lossy(&chars))
    }
}
