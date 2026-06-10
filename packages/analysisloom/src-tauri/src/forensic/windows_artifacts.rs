//! Windows execution artifacts — Prefetch (SCCA), shell links (LNK), Jump Lists.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsArtifact {
    pub artifact_type: String,
    pub name: String,
    pub source_path: String,
    pub executable: String,
    pub target_path: String,
    pub run_count: u32,
    pub last_run: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsScanResult {
    pub artifacts: Vec<WindowsArtifact>,
    pub prefetch_count: usize,
    pub lnk_count: usize,
    pub jump_list_count: usize,
}

pub fn scan_windows_artifacts(root: &str) -> Result<WindowsScanResult, String> {
    let root = Path::new(root);
    if !root.exists() {
        return Err(format!("Path not found: {}", root.display()));
    }

    let mut artifacts = vec![];
    collect_artifacts(root, 0, 6, &mut artifacts);

    let prefetch_count = artifacts
        .iter()
        .filter(|a| a.artifact_type == "prefetch")
        .count();
    let lnk_count = artifacts
        .iter()
        .filter(|a| a.artifact_type == "lnk")
        .count();
    let jump_list_count = artifacts
        .iter()
        .filter(|a| a.artifact_type == "jump_list")
        .count();

    Ok(WindowsScanResult {
        artifacts,
        prefetch_count,
        lnk_count,
        jump_list_count,
    })
}

fn collect_artifacts(dir: &Path, depth: u8, max_depth: u8, out: &mut Vec<WindowsArtifact>) {
    if depth > max_depth {
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
                if lower.ends_with(".pf") {
                    if let Ok(art) = parse_prefetch(&path) {
                        out.push(art);
                    }
                } else if lower.ends_with(".lnk") {
                    if let Ok(art) = parse_lnk(&path) {
                        out.push(art);
                    }
                } else if lower.ends_with("-automaticdestinations-ms")
                    || lower.ends_with("-customdestinations-ms")
                {
                    if let Ok(arts) = parse_jump_list(&path) {
                        out.extend(arts);
                    }
                }
            }
        } else if path.is_dir() {
            collect_artifacts(&path, depth + 1, max_depth, out);
        }
    }
}

pub fn parse_prefetch(path: &Path) -> Result<WindowsArtifact, String> {
    let data = std::fs::read(path).map_err(|e| format!("Read prefetch: {e}"))?;
    if data.len() < 0x48 {
        return Err("Prefetch file too small".into());
    }
    if &data[0..4] != b"SCCA" {
        return Err("Invalid SCCA signature".into());
    }

    let version = u32::from_le_bytes(
        data.get(4..8)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]),
    );
    let run_count = u32::from_le_bytes(
        data.get(0x48..0x4C)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]),
    );

    let executable = utf16_at(&data, 0x10, 30).unwrap_or_else(|| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    });

    let last_run = if data.len() >= 0x80 {
        let ft = u64::from_le_bytes(
            data.get(0x78..0x80)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 8]),
        );
        filetime_to_iso(ft)
    } else {
        "—".into()
    };

    Ok(WindowsArtifact {
        artifact_type: "prefetch".into(),
        name: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.pf")
            .into(),
        source_path: path.to_string_lossy().into(),
        executable,
        target_path: String::new(),
        run_count,
        last_run,
        details: format!("SCCA v{version}, run_count={run_count}"),
    })
}

pub fn parse_lnk(path: &Path) -> Result<WindowsArtifact, String> {
    let data = std::fs::read(path).map_err(|e| format!("Read LNK: {e}"))?;
    if data.len() < 0x4C {
        return Err("LNK file too small".into());
    }
    let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if header_size != 0x4C {
        return Err(format!("Unexpected LNK header size: {header_size}"));
    }

    let flags = u32::from_le_bytes(
        data.get(0x14..0x18)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 4]),
    );
    let (target, details) = extract_lnk_target(&data, flags);

    Ok(WindowsArtifact {
        artifact_type: "lnk".into(),
        name: path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.lnk")
            .into(),
        source_path: path.to_string_lossy().into(),
        executable: String::new(),
        target_path: target,
        run_count: 0,
        last_run: "—".into(),
        details,
    })
}

fn extract_lnk_target(data: &[u8], flags: u32) -> (String, String) {
    let mut offset = 0x4Cusize;
    let mut target = String::new();
    let details = format!("link_flags=0x{flags:08X}");

    if flags & 0x01 != 0 && offset + 2 <= data.len() {
        if let Some(bytes) = data.get(offset..offset + 2) {
            let id_size = u16::from_le_bytes(bytes.try_into().unwrap_or([0; 2])) as usize;
            offset += 2 + id_size;
        }
    }

    if flags & 0x02 != 0 && offset + 4 <= data.len() {
        let link_info_size = u32::from_le_bytes(
            data.get(offset..offset + 4)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 4]),
        ) as usize;
        if offset + link_info_size <= data.len() && link_info_size >= 0x1C {
            let li = &data[offset..offset + link_info_size];
            let local_base = u32::from_le_bytes(
                li.get(0x10..0x14)
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0; 4]),
            ) as usize;
            if local_base > 0 && local_base < li.len() {
                target = read_cstring(&li[local_base..]);
            }
        }
    }

    if target.is_empty() {
        target = scan_utf16_paths(data);
    }

    (target, details)
}

pub fn parse_jump_list(path: &Path) -> Result<Vec<WindowsArtifact>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Read jump list: {e}"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("jump_list")
        .to_string();

    let mut artifacts = vec![];
    let paths = extract_embedded_paths(&data);

    if paths.is_empty() {
        artifacts.push(WindowsArtifact {
            artifact_type: "jump_list".into(),
            name: name.clone(),
            source_path: path.to_string_lossy().into(),
            executable: String::new(),
            target_path: String::new(),
            run_count: 0,
            last_run: "—".into(),
            details: "OLE compound jump list — no embedded paths recovered".into(),
        });
    } else {
        for (i, p) in paths.iter().take(20).enumerate() {
            artifacts.push(WindowsArtifact {
                artifact_type: "jump_list".into(),
                name: format!("{name}#{i}"),
                source_path: path.to_string_lossy().into(),
                executable: String::new(),
                target_path: p.clone(),
                run_count: 0,
                last_run: "—".into(),
                details: "Recent file entry from AutomaticDestinations-ms".into(),
            });
        }
    }

    Ok(artifacts)
}

fn extract_embedded_paths(data: &[u8]) -> Vec<String> {
    let mut paths = vec![];
    let mut i = 0usize;
    while i + 4 < data.len() {
        if data[i] == b'C' || data[i] == b'D' || data[i] == b'E' {
            if let Some(s) = try_utf16_path_at(data, i) {
                if s.len() > 4 && s.contains('\\') && !paths.contains(&s) {
                    paths.push(s);
                }
            }
        }
        if data[i] == b':' && i > 0 && data[i - 1].is_ascii_alphabetic() {
            if let Some(s) = try_ascii_path_at(data, i - 1) {
                if s.len() > 4 && !paths.contains(&s) {
                    paths.push(s);
                }
            }
        }
        i += 1;
    }
    paths
}

fn try_utf16_path_at(data: &[u8], start: usize) -> Option<String> {
    let mut chars = vec![];
    let mut i = start;
    while i + 1 < data.len() && chars.len() < 260 {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);
        if ch == 0 {
            break;
        }
        if !(0x20..=0x7E).contains(&ch) {
            if chars.is_empty() {
                return None;
            }
            break;
        }
        chars.push(ch);
        i += 2;
    }
    if chars.len() < 4 {
        return None;
    }
    Some(String::from_utf16_lossy(&chars))
}

fn try_ascii_path_at(data: &[u8], start: usize) -> Option<String> {
    let slice = &data[start..data.len().min(start + 260)];
    let end = slice
        .iter()
        .position(|&b| b == 0 || b < 0x20)
        .unwrap_or(slice.len());
    let s = std::str::from_utf8(&slice[..end]).ok()?;
    if s.contains(':') && (s.contains('\\') || s.contains('/')) {
        Some(s.to_string())
    } else {
        None
    }
}

fn scan_utf16_paths(data: &[u8]) -> String {
    for i in 0..data.len().saturating_sub(8) {
        if let Some(s) = try_utf16_path_at(data, i) {
            if s.contains('\\') && s.len() > 6 {
                return s;
            }
        }
    }
    String::new()
}

fn utf16_at(data: &[u8], offset: usize, max_chars: usize) -> Option<String> {
    if offset + max_chars * 2 > data.len() {
        return None;
    }
    let mut chars = vec![];
    for i in 0..max_chars {
        let off = offset + i * 2;
        let ch = u16::from_le_bytes([data[off], data[off + 1]]);
        if ch == 0 {
            break;
        }
        chars.push(ch);
    }
    if chars.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&chars))
    }
}

fn read_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn filetime_to_iso(ft: u64) -> String {
    if ft == 0 {
        return "—".into();
    }
    let unix = (ft / 10_000_000).saturating_sub(11_644_473_600);
    chrono::DateTime::from_timestamp(unix as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "—".into())
}
