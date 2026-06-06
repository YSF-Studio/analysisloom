//! File preview — text, image (base64), hex. Pure Rust, no external image/archive crates.

use serde::{Deserialize, Serialize};
use std::path::Path;

use super::hashing::{check_magic_bytes, compute_entropy, multi_hash_buffer};

const TEXT_PREVIEW_LIMIT: usize = 50 * 1024;
const HEX_PREVIEW_LIMIT: usize = 4 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileKind {
    Text,
    Image,
    Archive,
    Binary,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewResult {
    pub path: String,
    pub filename: String,
    pub size: u64,
    pub kind: FileKind,
    pub mime_type: String,
    pub extension: String,
    pub preview: PreviewContent,
    pub metadata: FileMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreviewContent {
    Text(String),
    Image { data_base64: String, width: u32, height: u32 },
    HexDump(String),
    ArchiveList(Vec<String>),
    Unsupported(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub modified: String,
    pub created: String,
    pub permissions: String,
    pub is_dir: bool,
    pub magic_match: Option<String>,
    pub entropy: Option<f64>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

pub fn preview_file(path: &str) -> Result<PreviewResult, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("File not found: {path}"));
    }
    let meta = std::fs::metadata(path).map_err(|e| format!("Cannot read metadata: {e}"))?;
    let filename = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());
    let extension = p
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    #[cfg(unix)]
    let perms = {
        use std::os::unix::fs::PermissionsExt;
        format!("{:o}", meta.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let perms = "—".to_string();

    let modified = meta
        .modified()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "unknown".into());
    let created = meta
        .created()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "unknown".into());

    let kind = detect_kind(&extension);
    let data = std::fs::read(path).unwrap_or_default();
    let preview = generate_preview(&kind, &data)?;
    let hashes = multi_hash_buffer(&data);
    let entropy = Some(compute_entropy(&data));
    let magic_name = check_magic_bytes(&data);

    Ok(PreviewResult {
        path: path.to_string(),
        filename,
        size: meta.len(),
        kind,
        mime_type: mime_for(&extension),
        extension,
        preview,
        metadata: FileMetadata {
            size: meta.len(),
            modified,
            created,
            permissions: perms,
            is_dir: meta.is_dir(),
            magic_match: magic_name,
            entropy,
            md5: hashes.md5,
            sha1: hashes.sha1,
            sha256: hashes.sha256,
        },
    })
}

fn detect_kind(ext: &str) -> FileKind {
    match ext {
        "txt" | "md" | "csv" | "log" | "json" | "xml" | "html" | "htm" | "css" | "js" | "ts"
        | "rs" | "py" | "sql" | "ini" | "cfg" | "conf" => FileKind::Text,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "ico" | "svg" => FileKind::Image,
        "zip" | "tar" | "gz" => FileKind::Archive,
        _ => FileKind::Unknown,
    }
}

fn generate_preview(kind: &FileKind, data: &[u8]) -> Result<PreviewContent, String> {
    match kind {
        FileKind::Text => preview_text(data),
        FileKind::Image => preview_image(data),
        FileKind::Archive => Ok(PreviewContent::Unsupported(
            "Archive listing available via NTFS browser.".into(),
        )),
        FileKind::Binary | FileKind::Unknown => preview_hex(data),
    }
}

fn preview_text(data: &[u8]) -> Result<PreviewContent, String> {
    let text = String::from_utf8_lossy(data).to_string();
    let truncated = if text.len() > TEXT_PREVIEW_LIMIT {
        format!(
            "{}\n\n... [truncated at {} KB]",
            &text[..TEXT_PREVIEW_LIMIT],
            TEXT_PREVIEW_LIMIT / 1024
        )
    } else {
        text
    };
    Ok(PreviewContent::Text(truncated))
}

fn preview_image(data: &[u8]) -> Result<PreviewContent, String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let (width, height) = image_dimensions(data);
    Ok(PreviewContent::Image {
        data_base64: b64,
        width,
        height,
    })
}

fn image_dimensions(data: &[u8]) -> (u32, u32) {
    if data.len() >= 24 && data.starts_with(b"\x89PNG\r\n\x1a\n") {
        let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        return (w, h);
    }
    if data.len() >= 4 && data.starts_with(b"\xff\xd8\xff") {
        return (0, 0);
    }
    (0, 0)
}

fn preview_hex(data: &[u8]) -> Result<PreviewContent, String> {
    let limit = data.len().min(HEX_PREVIEW_LIMIT);
    let mut hex = String::from("\nOffset    Hex                                           ASCII\n");
    hex.push_str(&"-".repeat(80));
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        let offset = i * 16;
        let hex_part: String = chunk.iter().map(|b| format!("{b:02X} ")).collect();
        let ascii_part: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        hex.push_str(&format!("{offset:08X}  {hex_part:<48}  {ascii_part}\n"));
    }
    if data.len() > HEX_PREVIEW_LIMIT {
        hex.push_str(&format!(
            "\n... [showing first {} KB of {} KB total]",
            HEX_PREVIEW_LIMIT / 1024,
            data.len() / 1024
        ));
    }
    Ok(PreviewContent::HexDump(hex))
}

fn mime_for(ext: &str) -> String {
    match ext {
        "txt" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}
