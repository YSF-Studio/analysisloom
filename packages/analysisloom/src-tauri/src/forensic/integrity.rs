//! Evidence integrity — hash manifest verification & chain-of-custody (NIST SP 800-86 §3.4.1).

use super::hashing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFileEntry {
    pub path: Option<String>,
    pub relative_path: Option<String>,
    pub sha256: String,
    pub size_bytes: Option<u64>,
    pub acquired_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashManifest {
    pub source: Option<String>,
    pub exported_at: Option<String>,
    pub manifest_sha256: Option<String>,
    pub files: Vec<ManifestFileEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityVerifyResult {
    pub verified: bool,
    pub file_path: String,
    pub computed_sha256: String,
    pub expected_sha256: Option<String>,
    pub match_method: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashChainEntry {
    pub stage: String,
    pub file_path: String,
    pub acquisition_hash: Option<String>,
    pub analysis_hash: Option<String>,
    pub verified: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HashChainReport {
    pub manifest_loaded: bool,
    pub manifest_source: String,
    pub manifest_file_count: usize,
    pub entries: Vec<HashChainEntry>,
    pub all_verified: bool,
}

pub fn parse_hash_manifest(path: &str) -> Result<HashManifest, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read manifest: {e}"))?;
    let manifest: HashManifest =
        serde_json::from_str(&content).map_err(|e| format!("Invalid hash_manifest.json: {e}"))?;
    if manifest.files.is_empty() {
        return Err("Manifest contains no file entries".into());
    }
    Ok(manifest)
}

pub fn lookup_expected_hash(manifest: &HashManifest, file_path: &str) -> Option<String> {
    let path = Path::new(file_path);
    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or(file_path);

    for entry in &manifest.files {
        if entry.path.as_deref() == Some(file_path) {
            return Some(entry.sha256.clone());
        }
        if let Some(rel) = &entry.relative_path {
            if file_path.ends_with(rel) || file_path.contains(rel) {
                return Some(entry.sha256.clone());
            }
        }
        if entry.path.as_deref().map(|p| p.ends_with(fname)).unwrap_or(false) {
            return Some(entry.sha256.clone());
        }
        if entry.relative_path.as_deref().map(|r| r.ends_with(fname)).unwrap_or(false) {
            return Some(entry.sha256.clone());
        }
    }
    None
}

pub fn verify_file_hash(
    manifest: Option<&HashManifest>,
    file_path: &str,
    computed_sha256: &str,
) -> IntegrityVerifyResult {
    let computed = computed_sha256.to_lowercase();

    if let Some(m) = manifest {
        if let Some(expected) = lookup_expected_hash(m, file_path) {
            let exp = expected.to_lowercase();
            let verified = exp == computed;
            return IntegrityVerifyResult {
                verified,
                file_path: file_path.into(),
                computed_sha256: computed,
                expected_sha256: Some(exp),
                match_method: "hash_manifest.json".into(),
                message: if verified {
                    "SHA-256 matches acquisition manifest (CollectionLoom handoff)".into()
                } else {
                    "INTEGRITY FAIL: SHA-256 does not match hash_manifest.json — file may have been altered"
                        .into()
                },
            };
        }
    }

    IntegrityVerifyResult {
        verified: true,
        file_path: file_path.into(),
        computed_sha256: computed,
        expected_sha256: None,
        match_method: "none".into(),
        message: "No acquisition manifest loaded — hash computed but not verified against source"
            .into(),
    }
}

pub fn build_hash_chain_report(
    manifest: Option<&HashManifest>,
    evidence: &[(String, Option<String>)], // path, analysis sha256
) -> HashChainReport {
    let mut acquisition_map: HashMap<String, String> = HashMap::new();
    if let Some(m) = manifest {
        for f in &m.files {
            let hash = f.sha256.to_lowercase();
            if let Some(p) = &f.path {
                acquisition_map.insert(p.clone(), hash.clone());
            }
            if let Some(r) = &f.relative_path {
                acquisition_map.insert(r.clone(), hash);
            }
        }
    }

    let mut entries = vec![];
    let mut all_verified = manifest.is_some();

    for (path, analysis_hash) in evidence {
        let acq = lookup_expected_hash(manifest.unwrap_or(&HashManifest {
            source: None,
            exported_at: None,
            manifest_sha256: None,
            files: vec![],
        }), path)
        .or_else(|| {
            acquisition_map
                .get(path)
                .cloned()
                .or_else(|| {
                    Path::new(path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .and_then(|f| acquisition_map.get(f).cloned())
                })
        });

        let analysis = analysis_hash.as_ref().map(|h| h.to_lowercase());
        let verified = match (&acq, &analysis) {
            (Some(a), Some(b)) => a == b,
            (None, _) => !manifest.is_some(),
            (Some(_), None) => false,
        };
        if manifest.is_some() && !verified {
            all_verified = false;
        }

        entries.push(HashChainEntry {
            stage: if acq.is_some() { "Acquisition → Analysis" } else { "Analysis only" }.into(),
            file_path: path.clone(),
            acquisition_hash: acq,
            analysis_hash: analysis,
            verified,
            detail: if verified {
                "Hash chain intact".into()
            } else if manifest.is_some() {
                "Hash mismatch or missing analysis hash".into()
            } else {
                "No manifest — analysis hash recorded only".into()
            },
        });
    }

    HashChainReport {
        manifest_loaded: manifest.is_some(),
        manifest_source: manifest
            .and_then(|m| m.source.clone())
            .unwrap_or_else(|| "hash_manifest.json".into()),
        manifest_file_count: manifest.map(|m| m.files.len()).unwrap_or(0),
        entries,
        all_verified: manifest.map(|_| all_verified).unwrap_or(false),
    }
}

pub fn audit_chain_hash(prev_hash: &str, timestamp: &str, action: &str, detail: &str) -> String {
    let payload = format!("{prev_hash}|{timestamp}|{action}|{detail}");
    hashing::multi_hash_buffer(payload.as_bytes())
        .sha256
        .unwrap_or_default()
}

pub fn hash_chain_html(report: &HashChainReport) -> String {
    let status = if report.all_verified {
        r#"<p class="pass">✓ Hash chain verified — acquisition hashes match analysis hashes</p>"#
    } else if report.manifest_loaded {
        r#"<p class="fail">✗ Hash chain gaps detected — review entries below</p>"#
    } else {
        r#"<p class="warn">⚠ No acquisition manifest imported — analysis hashes recorded only</p>"#
    };

    let meta = format!(
        "<p><strong>Manifest source:</strong> {} &nbsp;|&nbsp; <strong>Files in manifest:</strong> {}</p>",
        html_escape(&report.manifest_source),
        report.manifest_file_count
    );

    if report.entries.is_empty() {
        return format!("{status}{meta}<p><em>No evidence items to validate</em></p>");
    }

    let rows: String = report
        .entries
        .iter()
        .map(|e| {
            let cls = if e.verified { "pass" } else { "fail" };
            format!(
                "<tr class=\"{cls}\"><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td></tr>",
                html_escape(&e.stage),
                e.acquisition_hash.as_deref().unwrap_or("—"),
                e.analysis_hash.as_deref().unwrap_or("—"),
                html_escape(&e.file_path),
                html_escape(&e.detail),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{status}{meta}<table class=\"chain\"><thead><tr><th>Stage</th><th>Acquisition SHA-256</th><th>Analysis SHA-256</th><th>File</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

pub fn hash_chain_text(report: &HashChainReport) -> String {
    let mut lines = vec![format!(
        "Manifest: {} ({} files) — {}",
        report.manifest_source,
        report.manifest_file_count,
        if report.all_verified {
            "ALL VERIFIED"
        } else if report.manifest_loaded {
            "GAPS DETECTED"
        } else {
            "NO MANIFEST"
        }
    )];
    for e in &report.entries {
        lines.push(format!(
            "{} | acq={} | analysis={} | {} | {}",
            e.stage,
            e.acquisition_hash.as_deref().unwrap_or("—"),
            e.analysis_hash.as_deref().unwrap_or("—"),
            e.file_path,
            e.detail,
        ));
    }
    lines.join("\n")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
