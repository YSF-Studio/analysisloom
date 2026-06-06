//! Steganography detection — LSB analysis and metadata anomalies in images.

use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StegoFinding {
    pub file_path: String,
    pub format: String,
    pub lsb_ratio: f64,
    pub chi_square: f64,
    pub suspicion_score: f64,
    pub verdict: String,
    pub metadata_anomalies: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StegoScanResult {
    pub findings: Vec<StegoFinding>,
    pub files_scanned: usize,
    pub suspicious_count: usize,
}

pub fn scan_images(paths: &[String]) -> StegoScanResult {
    let mut findings = vec![];
    for path in paths {
        let p = Path::new(path);
        if !p.is_file() {
            continue;
        }
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "bmp" | "gif" | "webp") {
            if let Ok(f) = analyze_image(path) {
                findings.push(f);
            }
        }
    }
    let suspicious_count = findings.iter().filter(|f| f.suspicion_score >= 0.6).count();
    StegoScanResult {
        files_scanned: findings.len(),
        suspicious_count,
        findings,
    }
}

pub fn analyze_image(path: &str) -> Result<StegoFinding, String> {
    let data = std::fs::read(path).map_err(|e| format!("Read image: {e}"))?;
    let format = detect_format(&data);
    let (pixels, anomalies) = match format.as_str() {
        "PNG" => extract_png_pixels(&data),
        "JPEG" => (vec![], vec!["JPEG LSB analysis limited to DCT domain heuristic".into()]),
        _ => (vec![], vec![]),
    };

    let metadata_anomalies = anomalies;
    let mut meta_extra = scan_chunk_text(&data);
    let mut all_anomalies = metadata_anomalies;
    all_anomalies.append(&mut meta_extra);

    let (lsb_ratio, chi_square) = if pixels.is_empty() {
        (0.0, 0.0)
    } else {
        (lsb_ones_ratio(&pixels), chi_square_lsb(&pixels))
    };

    let suspicion_score = compute_suspicion(lsb_ratio, chi_square, &all_anomalies);
    let verdict = if suspicion_score >= 0.75 {
        "high — possible hidden data"
    } else if suspicion_score >= 0.45 {
        "medium — anomalous LSB distribution"
    } else {
        "low — no strong stego indicators"
    };

    Ok(StegoFinding {
        file_path: path.into(),
        format,
        lsb_ratio,
        chi_square,
        suspicion_score,
        verdict: verdict.into(),
        metadata_anomalies: all_anomalies,
        details: format!(
            "LSB ratio={lsb_ratio:.3}, χ²={chi_square:.1}, score={suspicion_score:.2}"
        ),
    })
}

fn detect_format(data: &[u8]) -> String {
    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        "PNG".into()
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "JPEG".into()
    } else if data.starts_with(b"BM") {
        "BMP".into()
    } else if data.starts_with(b"GIF8") {
        "GIF".into()
    } else if data.starts_with(b"RIFF") && data.len() > 12 && &data[8..12] == b"WEBP" {
        "WEBP".into()
    } else {
        "unknown".into()
    }
}

fn extract_png_pixels(data: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut pixels = vec![];
    let mut anomalies = vec![];
    let mut pos = 8usize;
    let mut width = 0u32;
    let mut height = 0u32;

    while pos + 12 <= data.len() {
        let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let chunk_type = &data[pos + 4..pos + 8];
        let chunk_data_start = pos + 8;
        let chunk_data_end = chunk_data_start + len;

        if chunk_data_end > data.len() {
            break;
        }

        if chunk_type == b"IHDR" && len >= 8 {
            width = u32::from_be_bytes(data[chunk_data_start..chunk_data_start + 4].try_into().unwrap());
            height = u32::from_be_bytes(data[chunk_data_start + 4..chunk_data_start + 8].try_into().unwrap());
        } else if chunk_type == b"IDAT" {
            pixels.extend_from_slice(&data[chunk_data_start..chunk_data_end]);
        } else if chunk_type == b"tEXt" || chunk_type == b"iTXt" || chunk_type == b"zTXt" {
            let text = String::from_utf8_lossy(&data[chunk_data_start..chunk_data_end]);
            if text.to_lowercase().contains("hidden")
                || text.to_lowercase().contains("secret")
                || text.to_lowercase().contains("stego")
            {
                anomalies.push(format!("Suspicious {} chunk: {}", String::from_utf8_lossy(chunk_type), text.chars().take(80).collect::<String>()));
            }
        }

        pos = chunk_data_end + 4;
    }

    if width > 0 && height > 0 && pixels.is_empty() {
        anomalies.push(format!("PNG {width}×{height} — IDAT compressed, LSB on raw deflate bytes"));
    }

    (pixels, anomalies)
}

fn scan_chunk_text(data: &[u8]) -> Vec<String> {
    let mut found = vec![];
    let needles: &[&[u8]] = &[b"hidden", b"secret", b"password", b"stego", b"encrypted"];
    for needle in needles {
        if data.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle)) {
            found.push(format!(
                "Embedded keyword '{}' in file bytes",
                String::from_utf8_lossy(needle)
            ));
        }
    }
    found
}

fn lsb_ones_ratio(pixels: &[u8]) -> f64 {
    if pixels.is_empty() {
        return 0.0;
    }
    let ones = pixels.iter().map(|b| (b & 1) as u32).sum::<u32>();
    ones as f64 / pixels.len() as f64
}

fn chi_square_lsb(pixels: &[u8]) -> f64 {
    let mut freq = [0u32; 2];
    for &b in pixels {
        freq[(b & 1) as usize] += 1;
    }
    let n = pixels.len() as f64;
    if n < 2.0 {
        return 0.0;
    }
    let expected = n / 2.0;
    let chi = freq
        .iter()
        .map(|&f| {
            let diff = f as f64 - expected;
            diff * diff / expected
        })
        .sum::<f64>();
    chi
}

fn compute_suspicion(lsb_ratio: f64, chi_square: f64, anomalies: &[String]) -> f64 {
    let mut score = 0.0f64;
    let deviation = (lsb_ratio - 0.5).abs();
    if deviation > 0.08 {
        score += (deviation * 4.0).min(0.4);
    }
    if chi_square > 50.0 {
        score += ((chi_square - 50.0) / 200.0).min(0.35);
    }
    score += (anomalies.len() as f64 * 0.15).min(0.35);
    score.min(1.0)
}
