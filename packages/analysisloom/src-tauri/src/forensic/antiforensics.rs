//! Anti-forensics detection: timestomp, extension mismatch, ADS, zero-size anomalies.

use super::carving::MAGIC_SIGNATURES;
use super::ntfs::MftEntry;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AntiForensicsFinding {
    pub detection_type: String,
    pub file_path: String,
    pub severity: String,
    pub details: String,
    pub record_number: Option<u64>,
}

pub fn analyze_mft_entries(entries: &[MftEntry], image_path: &str) -> Vec<AntiForensicsFinding> {
    let mut findings = vec![];
    for entry in entries {
        findings.extend(check_timestomp(entry, image_path));
        findings.extend(check_zero_size(entry, image_path));
        findings.extend(check_ads(entry, image_path));
        if entry.is_deleted {
            findings.push(AntiForensicsFinding {
                detection_type: "Deleted MFT Entry".into(),
                file_path: format!("{image_path}::{}", entry.filename),
                severity: "medium".into(),
                details: "File marked deleted in MFT — recovery may be possible via carving".into(),
                record_number: Some(entry.record_number),
            });
        }
    }
    findings
}

fn check_timestomp(entry: &MftEntry, image_path: &str) -> Vec<AntiForensicsFinding> {
    let mut out = vec![];
    if let (Some(si), Some(fn_c)) = (&entry.si_created, &entry.fn_created) {
        if si != fn_c && !si.contains("invalid") && !fn_c.contains("invalid") {
            out.push(AntiForensicsFinding {
                detection_type: "Timestomp Suspect".into(),
                file_path: format!("{image_path}::{}", entry.filename),
                severity: "high".into(),
                details: format!(
                    "$STANDARD_INFORMATION created ({si}) differs from $FILE_NAME ({fn_c}) — possible timestomp"
                ),
                record_number: Some(entry.record_number),
            });
        }
    }
    if let (Some(si_m), Some(fn_m)) = (&entry.si_modified, &entry.fn_modified) {
        if si_m != fn_m && !si_m.contains("invalid") {
            out.push(AntiForensicsFinding {
                detection_type: "MACB Mismatch".into(),
                file_path: format!("{image_path}::{}", entry.filename),
                severity: "medium".into(),
                details: format!("$SI modified ({si_m}) vs $FN modified ({fn_m})"),
                record_number: Some(entry.record_number),
            });
        }
    }
    out
}

fn check_zero_size(entry: &MftEntry, image_path: &str) -> Vec<AntiForensicsFinding> {
    if !entry.is_directory && entry.file_size == 0 && entry.has_data {
        return vec![AntiForensicsFinding {
            detection_type: "Zero-Size Anomaly".into(),
            file_path: format!("{image_path}::{}", entry.filename),
            severity: "medium".into(),
            details: "File reports 0 bytes but has $DATA attribute — possible hidden content".into(),
            record_number: Some(entry.record_number),
        }];
    }
    vec![]
}

fn check_ads(entry: &MftEntry, image_path: &str) -> Vec<AntiForensicsFinding> {
    entry
        .attributes
        .iter()
        .filter(|a| a.attr_type == "$DATA" && a.name.is_some())
        .map(|a| AntiForensicsFinding {
            detection_type: "NTFS Alternate Data Stream".into(),
            file_path: format!("{image_path}::{}:{}", entry.filename, a.name.as_deref().unwrap_or("")),
            severity: "high".into(),
            details: format!(
                "Named data stream '{}' ({} bytes) — common anti-forensics / Zone.Identifier vector",
                a.name.as_deref().unwrap_or(""),
                a.size
            ),
            record_number: Some(entry.record_number),
        })
        .collect()
}

pub fn check_extension_mismatch(path: &str) -> Result<Option<AntiForensicsFinding>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    if data.len() < 4 {
        return Ok(None);
    }
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let detected = MAGIC_SIGNATURES
        .iter()
        .find(|(magic, _)| data.len() >= magic.len() && &data[..magic.len()] == *magic)
        .map(|(_, t)| *t);

    let expected_ext = match detected {
        Some("JPEG") => "jpg",
        Some("PNG") => "png",
        Some("PDF") => "pdf",
        Some("ZIP") => "zip",
        Some("PE (EXE/DLL)") => "exe",
        Some("SQLite DB") => "db",
        _ => return Ok(None),
    };

    if ext != expected_ext && !ext.is_empty() {
        let type_name = detected.unwrap_or("unknown");
        return Ok(Some(AntiForensicsFinding {
            detection_type: "Extension Mismatch".into(),
            file_path: path.into(),
            severity: "high".into(),
            details: format!(
                "File extension '.{ext}' does not match detected type '{type_name}' (magic bytes) — possible masquerading"
            ),
            record_number: None,
        }));
    }
    Ok(None)
}

pub fn scan_evidence_files(paths: &[String]) -> Vec<AntiForensicsFinding> {
    let mut findings = vec![];
    for path in paths {
        if let Ok(Some(f)) = check_extension_mismatch(path) {
            findings.push(f);
        }
    }
    findings
}
