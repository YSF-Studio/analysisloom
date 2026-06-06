//! Case evidence bundle export — ZIP with manifest, hashes, and reports.

use super::hashing;
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Write};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleFileEntry {
    pub archive_path: String,
    pub source_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub item_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleManifest {
    pub case_id: String,
    pub case_name: String,
    pub operator: String,
    pub created_at: String,
    pub exported_at: String,
    pub files: Vec<BundleFileEntry>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleExportResult {
    pub zip_path: String,
    pub file_count: usize,
    pub manifest_sha256: String,
    pub total_bytes: u64,
}

pub fn create_case_bundle(
    case_id: &str,
    case_name: &str,
    operator: &str,
    output_path: &str,
    evidence: &[(String, String, Option<String>, i64)], // path, type, sha256, size
    report_html: &str,
    report_pdf: Option<&[u8]>,
    findings_json: &str,
    audit_json: &str,
) -> Result<BundleExportResult, String> {
    let file = File::create(output_path).map_err(|e| format!("Cannot create ZIP: {e}"))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut manifest_files = vec![];
    let mut total_bytes = 0u64;

    for (idx, (source, item_type, sha256_opt, size)) in evidence.iter().enumerate() {
        let src = std::path::Path::new(source);
        if !src.is_file() {
            continue;
        }
        let name = src
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("evidence");
        let archive_path = format!("evidence/{idx:03}_{name}");
        let sha256 = sha256_opt.clone().unwrap_or_else(|| {
            hashing::multi_hash_file(source)
                .ok()
                .and_then(|h| h.sha256)
                .unwrap_or_default()
        });
        let mut f = std::fs::File::open(source).map_err(|e| e.to_string())?;
        let mut buf = vec![];
        f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        total_bytes += buf.len() as u64;

        zip.start_file(&archive_path, options)
            .map_err(|e| e.to_string())?;
        zip.write_all(&buf).map_err(|e| e.to_string())?;

        manifest_files.push(BundleFileEntry {
            archive_path,
            source_path: source.clone(),
            sha256,
            size_bytes: if *size > 0 { *size as u64 } else { buf.len() as u64 },
            item_type: item_type.clone(),
        });
    }

    zip.start_file("report/case_report.html", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(report_html.as_bytes())
        .map_err(|e| e.to_string())?;
    total_bytes += report_html.len() as u64;

    if let Some(pdf) = report_pdf {
        zip.start_file("report/case_report.pdf", options)
            .map_err(|e| e.to_string())?;
        zip.write_all(pdf).map_err(|e| e.to_string())?;
        total_bytes += pdf.len() as u64;
    }

    zip.start_file("findings.json", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(findings_json.as_bytes())
        .map_err(|e| e.to_string())?;

    zip.start_file("audit_log.json", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(audit_json.as_bytes())
        .map_err(|e| e.to_string())?;

    let exported_at = chrono::Utc::now().to_rfc3339();
    let manifest = BundleManifest {
        case_id: case_id.into(),
        case_name: case_name.into(),
        operator: operator.into(),
        created_at: exported_at.clone(),
        exported_at,
        manifest_sha256: String::new(),
        files: manifest_files.clone(),
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    let manifest_sha256 = hashing::multi_hash_buffer(manifest_json.as_bytes())
        .sha256
        .unwrap_or_default();

    let manifest_final = BundleManifest {
        manifest_sha256: manifest_sha256.clone(),
        ..manifest
    };
    let manifest_json = serde_json::to_string_pretty(&manifest_final).map_err(|e| e.to_string())?;

    zip.start_file("manifest.json", options)
        .map_err(|e| e.to_string())?;
    zip.write_all(manifest_json.as_bytes())
        .map_err(|e| e.to_string())?;

    zip.start_file("README.txt", options)
        .map_err(|e| e.to_string())?;
    let readme = format!(
        "AnalysisLoom Evidence Bundle\nCase: {case_name}\nCase ID: {case_id}\nFiles: {}\nManifest SHA-256: {manifest_sha256}\n",
        manifest_files.len()
    );
    zip.write_all(readme.as_bytes()).map_err(|e| e.to_string())?;

    zip.finish().map_err(|e| e.to_string())?;

    Ok(BundleExportResult {
        zip_path: output_path.into(),
        file_count: manifest_files.len(),
        manifest_sha256,
        total_bytes,
    })
}
