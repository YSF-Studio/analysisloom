//! Encrypted volume / container detection — BitLocker, LUKS, VeraCrypt heuristics.

use serde::{Deserialize, Serialize};
use std::io::Read;

use super::hashing::compute_entropy;
use super::ntfs;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedFinding {
    pub detection_type: String,
    pub location: String,
    pub offset: u64,
    pub confidence: f64,
    pub entropy: Option<f64>,
    pub details: String,
}

const MFT_NAME_MARKERS: &[(&str, &str, f64)] = &[
    ("bitlocker", "BitLocker", 0.92),
    (".bek", "BitLocker", 0.88),
    ("fveinfo", "BitLocker", 0.85),
    ("fve-", "BitLocker", 0.80),
    ("veracrypt", "VeraCrypt", 0.90),
    (".hc", "VeraCrypt", 0.75),
    ("filevault", "FileVault", 0.85),
    ("encrypted", "Encrypted", 0.70),
    (".dmg", "EncryptedDMG", 0.55),
];

/// Scan disk image for encryption indicators (signatures, MFT names, entropy).
pub fn detect_encrypted(image_path: &str) -> Result<Vec<EncryptedFinding>, String> {
    let mut findings = vec![];
    let mut file =
        std::fs::File::open(image_path).map_err(|e| format!("Cannot open image: {e}"))?;
    let file_size = file.metadata().map_err(|e| e.to_string())?.len();

    let mut boot = vec![0u8; 4096];
    let boot_len = file
        .read(&mut boot)
        .map_err(|e| format!("Read error: {e}"))?;
    boot.truncate(boot_len);

    scan_signatures(&boot, 0, &mut findings);
    scan_high_entropy(&boot, 0, "Boot sector", &mut findings);

    // Sample at 1 MiB and 1 GiB for partition-level encryption headers
    for offset in [1024 * 1024, 1024 * 1024 * 1024] {
        if offset >= file_size {
            continue;
        }
        if let Ok(sample) = read_at(&mut file, offset, 4096) {
            scan_signatures(&sample, offset, &mut findings);
            scan_high_entropy(&sample, offset, "Partition sample", &mut findings);
        }
    }

    let cancel = std::sync::atomic::AtomicBool::new(false);
    if let Ok(entries) = ntfs::parse_mft(image_path, &cancel) {
        for entry in entries {
            let lower = entry.filename.to_lowercase();
            for (marker, vol_type, confidence) in MFT_NAME_MARKERS {
                if lower.contains(marker) {
                    findings.push(EncryptedFinding {
                        detection_type: vol_type.to_string(),
                        location: entry.filename.clone(),
                        offset: entry.record_number,
                        confidence: *confidence,
                        entropy: None,
                        details: format!(
                            "MFT record #{} — possible {} artifact",
                            entry.record_number, vol_type
                        ),
                    });
                    break;
                }
            }
        }
    }

    dedupe_findings(&mut findings);
    findings.retain(|f| f.confidence >= 0.55 && f.detection_type != "GPT");
    findings.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(findings)
}

fn read_at(file: &mut std::fs::File, offset: u64, len: usize) -> Result<Vec<u8>, String> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("Seek error: {e}"))?;
    let mut buf = vec![0u8; len];
    let n = file
        .read(&mut buf)
        .map_err(|e| format!("Read error: {e}"))?;
    buf.truncate(n);
    Ok(buf)
}

fn scan_signatures(data: &[u8], base_offset: u64, findings: &mut Vec<EncryptedFinding>) {
    const SIGNATURES: &[(&[u8], &str, f64, &str)] = &[
        (b"LUKS\xba\xbe", "LUKS", 0.95, "LUKS partition header magic"),
        (
            b"-FVE-FS-",
            "BitLocker",
            0.93,
            "BitLocker FVE filesystem marker",
        ),
        (b"FVE-FS-", "BitLocker", 0.90, "BitLocker FVE header"),
        (
            b"EFI PART",
            "GPT",
            0.40,
            "GPT partition table (check nested volumes)",
        ),
        (
            b"Salted__",
            "FileVault",
            0.88,
            "FileVault/DMG salted header",
        ),
    ];

    for (magic, vol_type, confidence, detail) in SIGNATURES {
        if let Some(pos) = find_bytes(data, magic) {
            findings.push(EncryptedFinding {
                detection_type: (*vol_type).to_string(),
                location: format!("offset 0x{pos:X}"),
                offset: base_offset + pos as u64,
                confidence: *confidence,
                entropy: Some(compute_entropy(
                    &data[pos..pos + magic.len().min(data.len() - pos)],
                )),
                details: (*detail).to_string(),
            });
        }
    }
}

fn scan_high_entropy(
    data: &[u8],
    base_offset: u64,
    region: &str,
    findings: &mut Vec<EncryptedFinding>,
) {
    if data.len() < 512 {
        return;
    }
    let entropy = compute_entropy(data);
    if entropy >= 7.8 {
        findings.push(EncryptedFinding {
            detection_type: "HighEntropy".into(),
            location: format!("{region} @ 0x{base_offset:X}"),
            offset: base_offset,
            confidence: if entropy >= 7.95 { 0.82 } else { 0.65 },
            entropy: Some(entropy),
            details: format!(
                "Shannon entropy {entropy:.2} — possible full-disk encryption or compressed container"
            ),
        });
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn dedupe_findings(findings: &mut Vec<EncryptedFinding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = format!("{}:{}:{}", f.detection_type, f.location, f.offset);
        seen.insert(key)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_luks_magic() {
        let mut data = vec![0u8; 512];
        data[0..6].copy_from_slice(b"LUKS\xba\xbe");
        let mut findings = vec![];
        scan_signatures(&data, 0, &mut findings);
        assert!(findings.iter().any(|f| f.detection_type == "LUKS"));
    }

    #[test]
    fn high_entropy_detected() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let mut findings = vec![];
        scan_high_entropy(&data, 0, "test", &mut findings);
        assert!(!findings.is_empty());
    }
}
