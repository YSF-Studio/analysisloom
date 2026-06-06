//! Windows registry hive analyzer (SAM / SYSTEM / SOFTWARE / NTUSER.DAT).

use serde::Serialize;

const HIVE_HEADER_SIZE: usize = 4096;
const FIRST_HBIN: usize = 4096;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryFinding {
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub category: String,
    pub forensic_relevance: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryScanResult {
    pub hive_type: String,
    pub findings: Vec<RegistryFinding>,
    pub keys_scanned: usize,
}

pub fn analyze_hive(path: &str) -> Result<RegistryScanResult, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read hive: {e}"))?;
    if data.len() < HIVE_HEADER_SIZE {
        return Err("File too small for registry hive".into());
    }
    if &data[0..4] != b"regf" {
        return Err("Not a registry hive (missing regf header)".into());
    }

    let hive_type = detect_hive_type(path);
    let root_off = i32::from_le_bytes([data[0x24], data[0x25], data[0x26], data[0x27]]) as isize;
    let root_abs = FIRST_HBIN + root_off as usize;

    let mut findings = vec![];
    let mut keys_scanned = 0usize;

    let forensic_paths: Vec<(&str, &str, &str)> = match hive_type.as_str() {
        "SYSTEM" => vec![
            ("ControlSet001\\Enum\\USBSTOR", "USB History", "usb"),
            ("ControlSet001\\Services\\USBSTOR", "USB Driver", "usb"),
            ("MountedDevices", "Mounted Volumes", "mount"),
        ],
        "SOFTWARE" => vec![
            (
                "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                "UserAssist / Program Execution",
                "userassist",
            ),
            (
                "Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
                "User Profiles",
                "profiles",
            ),
            (
                "Microsoft\\Windows\\CurrentVersion\\Run",
                "Autorun (Run)",
                "persistence",
            ),
            (
                "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Autorun (RunOnce)",
                "persistence",
            ),
        ],
        "NTUSER" => vec![
            (
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
                "Recent Documents (MRU)",
                "mru",
            ),
            (
                "Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Shellbags",
                "shellbags",
            ),
            (
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
                "Open/Save Dialog MRU",
                "mru",
            ),
            (
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
                "Typed Paths",
                "mru",
            ),
        ],
        "SAM" => vec![("SAM\\Domains\\Account\\Users", "Local Accounts", "accounts")],
        _ => vec![],
    };

    for (subpath, label, category) in forensic_paths {
        keys_scanned += 1;
        if let Some(key_off) = find_key_path(&data, root_abs, subpath) {
            collect_key_values(
                &data,
                key_off,
                &hive_type,
                subpath,
                label,
                category,
                &mut findings,
            );
            collect_subkeys(
                &data,
                key_off,
                &hive_type,
                subpath,
                category,
                &mut findings,
                2,
            );
        } else {
            findings.push(RegistryFinding {
                hive: hive_type.clone(),
                key_path: subpath.into(),
                value_name: "(key)".into(),
                value_data: "Path not found in hive".into(),
                category: category.into(),
                forensic_relevance: format!("{label} — not present"),
            });
        }
    }

    Ok(RegistryScanResult {
        hive_type,
        findings,
        keys_scanned,
    })
}

fn detect_hive_type(path: &str) -> String {
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_uppercase();
    if name.contains("SYSTEM") {
        "SYSTEM".into()
    } else if name.contains("SOFTWARE") {
        "SOFTWARE".into()
    } else if name.contains("NTUSER") {
        "NTUSER".into()
    } else if name.contains("SAM") {
        "SAM".into()
    } else if name.contains("SECURITY") {
        "SECURITY".into()
    } else {
        "UNKNOWN".into()
    }
}

fn cell_data(data: &[u8], abs_offset: usize) -> Option<&[u8]> {
    if abs_offset + 4 > data.len() {
        return None;
    }
    let size = i32::from_le_bytes([
        data[abs_offset],
        data[abs_offset + 1],
        data[abs_offset + 2],
        data[abs_offset + 3],
    ]);
    let len = size.unsigned_abs() as usize;
    if abs_offset + len > data.len() || len < 4 {
        return None;
    }
    Some(&data[abs_offset..abs_offset + len])
}

fn find_key_path(data: &[u8], root: usize, path: &str) -> Option<usize> {
    let mut current = root;
    for part in path.split('\\') {
        current = find_subkey(data, current, part)?;
    }
    Some(current)
}

fn find_subkey(data: &[u8], key_off: usize, name: &str) -> Option<usize> {
    let cell = cell_data(data, key_off)?;
    if cell.len() < 0x4c || &cell[0..2] != b"nk" {
        return None;
    }
    let subkeys_list =
        i32::from_le_bytes([cell[0x24], cell[0x25], cell[0x26], cell[0x27]]) as isize;
    let subkey_count =
        i32::from_le_bytes([cell[0x28], cell[0x29], cell[0x2a], cell[0x2b]]) as usize;
    if subkey_count == 0 {
        return None;
    }
    let list_abs = key_off as isize + subkeys_list;
    if list_abs < 0 {
        return None;
    }
    let list_cell = cell_data(data, list_abs as usize)?;
    if list_cell.len() < 8
        || &list_cell[0..2] != b"lf"
            && &list_cell[0..2] != b"lh"
            && &list_cell[0..2] != b"ri"
            && &list_cell[0..2] != b"li"
    {
        return walk_subkeys_linear(data, key_off, name);
    }
    let count = u16::from_le_bytes([list_cell[0x04], list_cell[0x05]]) as usize;
    for i in 0..count {
        let entry_off = 0x08 + i * 8;
        if entry_off + 8 > list_cell.len() {
            break;
        }
        let child_rel = i32::from_le_bytes([
            list_cell[entry_off],
            list_cell[entry_off + 1],
            list_cell[entry_off + 2],
            list_cell[entry_off + 3],
        ]) as isize;
        let child_abs = key_off as isize + child_rel;
        if child_abs < 0 {
            continue;
        }
        if let Some(child_cell) = cell_data(data, child_abs as usize) {
            if child_cell.len() >= 0x4c && &child_cell[0..2] == b"nk" {
                let key_name = read_key_name(child_cell);
                if key_name.eq_ignore_ascii_case(name) {
                    return Some(child_abs as usize);
                }
            }
        }
    }
    walk_subkeys_linear(data, key_off, name)
}

fn walk_subkeys_linear(data: &[u8], key_off: usize, name: &str) -> Option<usize> {
    let cell = cell_data(data, key_off)?;
    let subkey_count =
        i32::from_le_bytes([cell[0x28], cell[0x29], cell[0x2a], cell[0x2b]]) as usize;
    let mut sub_off_rel =
        i32::from_le_bytes([cell[0x2c], cell[0x2d], cell[0x2e], cell[0x2f]]) as isize;
    for _ in 0..subkey_count {
        if sub_off_rel == 0 {
            break;
        }
        let sub_abs = key_off as isize + sub_off_rel;
        if sub_abs < 0 {
            break;
        }
        if let Some(sub_cell) = cell_data(data, sub_abs as usize) {
            if sub_cell.len() >= 0x4c && &sub_cell[0..2] == b"nk" {
                let key_name = read_key_name(sub_cell);
                if key_name.eq_ignore_ascii_case(name) {
                    return Some(sub_abs as usize);
                }
                sub_off_rel = i32::from_le_bytes([
                    sub_cell[0x2c],
                    sub_cell[0x2d],
                    sub_cell[0x2e],
                    sub_cell[0x2f],
                ]) as isize;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    None
}

fn read_key_name(cell: &[u8]) -> String {
    let name_len = u16::from_le_bytes([cell[0x4a], cell[0x4b]]) as usize;
    let flags = cell[0x48];
    if flags & 0x20 != 0 {
        // compressed ASCII
        let end = (0x4c + name_len).min(cell.len());
        String::from_utf8_lossy(&cell[0x4c..end]).to_string()
    } else {
        let end = (0x4c + name_len * 2).min(cell.len());
        String::from_utf16_lossy(
            &cell[0x4c..end]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect::<Vec<_>>(),
        )
    }
}

fn collect_key_values(
    data: &[u8],
    key_off: usize,
    hive: &str,
    key_path: &str,
    label: &str,
    category: &str,
    findings: &mut Vec<RegistryFinding>,
) {
    let cell = match cell_data(data, key_off) {
        Some(c) => c,
        None => return,
    };
    if cell.len() < 0x4c || &cell[0..2] != b"nk" {
        return;
    }
    let value_count = i32::from_le_bytes([cell[0x2c], cell[0x2d], cell[0x2e], cell[0x2f]]) as usize;
    let mut val_off_rel =
        i32::from_le_bytes([cell[0x30], cell[0x31], cell[0x32], cell[0x33]]) as isize;

    for _ in 0..value_count.min(64) {
        if val_off_rel == 0 {
            break;
        }
        let val_abs = key_off as isize + val_off_rel;
        if val_abs < 0 {
            break;
        }
        if let Some(val_cell) = cell_data(data, val_abs as usize) {
            if val_cell.len() >= 0x18 && &val_cell[0..2] == b"vk" {
                let (vname, vdata) = read_value(val_cell, data, val_abs as usize);
                findings.push(RegistryFinding {
                    hive: hive.into(),
                    key_path: key_path.into(),
                    value_name: vname,
                    value_data: vdata,
                    category: category.into(),
                    forensic_relevance: label.into(),
                });
                val_off_rel = i32::from_le_bytes([
                    val_cell[0x04],
                    val_cell[0x05],
                    val_cell[0x06],
                    val_cell[0x07],
                ]) as isize;
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn read_value(val_cell: &[u8], data: &[u8], val_abs: usize) -> (String, String) {
    let name_len = u16::from_le_bytes([val_cell[0x02], val_cell[0x03]]) as usize;
    let data_len = i32::from_le_bytes([
        val_cell[0x08],
        val_cell[0x09],
        val_cell[0x0a],
        val_cell[0x0b],
    ]);
    let data_off = i32::from_le_bytes([
        val_cell[0x0c],
        val_cell[0x0d],
        val_cell[0x0e],
        val_cell[0x0f],
    ]);
    let data_type = u32::from_le_bytes([
        val_cell[0x10],
        val_cell[0x11],
        val_cell[0x12],
        val_cell[0x13],
    ]);

    let name = if name_len > 0 && val_cell.len() >= 0x18 + name_len {
        String::from_utf8_lossy(&val_cell[0x18..0x18 + name_len]).to_string()
    } else {
        "(default)".into()
    };

    let value = if data_len <= 4 {
        format!("0x{:08X}", data_off as u32)
    } else if data_len > 0 && data_len < 1_000_000 {
        let abs = if data_off >= 0 {
            val_abs as isize + data_off as isize
        } else {
            FIRST_HBIN as isize + data_off as isize
        };
        if abs >= 0 && (abs as usize) < data.len() {
            decode_value_data(&data[abs as usize..], data_type, data_len as usize)
        } else {
            "(unreadable)".into()
        }
    } else {
        "(large data)".into()
    };
    (name, value)
}

fn decode_value_data(raw: &[u8], data_type: u32, len: usize) -> String {
    let slice = &raw[..len.min(raw.len())];
    match data_type {
        1 | 2 => String::from_utf8_lossy(slice).to_string(),
        3 | 5 => format!(
            "DWORD: {}",
            u32::from_le_bytes([
                slice[0],
                slice.get(1).copied().unwrap_or(0),
                slice.get(2).copied().unwrap_or(0),
                slice.get(3).copied().unwrap_or(0)
            ])
        ),
        7 => {
            if slice.len() >= 8 {
                format_hex_preview(slice, 32)
            } else {
                format_hex_preview(slice, slice.len())
            }
        }
        _ => format_hex_preview(slice, 24),
    }
}

fn format_hex_preview(data: &[u8], max: usize) -> String {
    data.iter()
        .take(max)
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn collect_subkeys(
    data: &[u8],
    key_off: usize,
    hive: &str,
    parent_path: &str,
    category: &str,
    findings: &mut Vec<RegistryFinding>,
    depth: u8,
) {
    if depth == 0 {
        return;
    }
    let cell = match cell_data(data, key_off) {
        Some(c) => c,
        None => return,
    };
    let subkey_count =
        i32::from_le_bytes([cell[0x28], cell[0x29], cell[0x2a], cell[0x2b]]) as usize;
    let mut sub_off_rel =
        i32::from_le_bytes([cell[0x2c], cell[0x2d], cell[0x2e], cell[0x2f]]) as isize;

    for _ in 0..subkey_count.min(32) {
        if sub_off_rel == 0 {
            break;
        }
        let sub_abs = key_off as isize + sub_off_rel;
        if sub_abs < 0 {
            break;
        }
        if let Some(sub_cell) = cell_data(data, sub_abs as usize) {
            if sub_cell.len() >= 0x4c && &sub_cell[0..2] == b"nk" {
                let name = read_key_name(sub_cell);
                let full_path = format!("{parent_path}\\{name}");
                findings.push(RegistryFinding {
                    hive: hive.into(),
                    key_path: full_path.clone(),
                    value_name: "(subkey)".into(),
                    value_data: name,
                    category: category.into(),
                    forensic_relevance: "Subkey enumeration".into(),
                });
                collect_subkeys(
                    data,
                    sub_abs as usize,
                    hive,
                    &full_path,
                    category,
                    findings,
                    depth - 1,
                );
                sub_off_rel = i32::from_le_bytes([
                    sub_cell[0x2c],
                    sub_cell[0x2d],
                    sub_cell[0x2e],
                    sub_cell[0x2f],
                ]) as isize;
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

pub fn scan_hives_in_directory(dir: &str) -> Result<Vec<RegistryScanResult>, String> {
    let mut results = vec![];
    let targets = ["SYSTEM", "SOFTWARE", "SAM", "NTUSER.DAT"];
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_uppercase();
        if targets.iter().any(|t| fname.contains(t)) {
            if let Ok(r) = analyze_hive(path.to_string_lossy().as_ref()) {
                results.push(r);
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_hive() {
        let path = std::env::temp_dir().join("not_a_hive.dat");
        std::fs::write(&path, b"not a registry hive").unwrap();
        let err = analyze_hive(path.to_string_lossy().as_ref()).unwrap_err();
        assert!(err.contains("regf") || err.contains("too small"));
        let _ = std::fs::remove_file(path);
    }
}
