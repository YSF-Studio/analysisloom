//! Random forensic test fixtures — NTFS image, SQLite DB, carving payloads, evidence files.

use rand::{rngs::StdRng, Rng, SeedableRng};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct TestWorkspace {
    pub root: PathBuf,
    pub ntfs_image: PathBuf,
    pub luks_image: PathBuf,
    pub carve_image: PathBuf,
    pub sqlite_db: PathBuf,
    pub evidence_txt: PathBuf,
    pub evidence_png: PathBuf,
    pub carve_output: PathBuf,
}

pub fn generate_workspace(seed: u64) -> TestWorkspace {
    let root = std::env::temp_dir().join(format!("analysisloom_test_{seed}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create workspace");
    std::fs::create_dir_all(root.join("carved")).expect("create carved dir");

    let mut rng = StdRng::seed_from_u64(seed);

    let ntfs_image = root.join("random_ntfs.dd");
    write_ntfs_image(&ntfs_image, &mut rng);

    let luks_image = root.join("luks_volume.dd");
    write_luks_image(&luks_image, &mut rng);

    let carve_image = root.join("carve_source.dd");
    write_carve_image(&carve_image, &mut rng);

    let sqlite_db = root.join("messages.db");
    write_sqlite_db(&sqlite_db, &mut rng);

    let evidence_txt = root.join("secret_password_log.txt");
    write_evidence_text(&evidence_txt, &mut rng);

    let evidence_png = root.join("photo_evidence.png");
    write_minimal_png(&evidence_png);

    TestWorkspace {
        root: root.clone(),
        ntfs_image,
        luks_image,
        carve_image,
        sqlite_db,
        evidence_txt,
        evidence_png,
        carve_output: root.join("carved"),
    }
}

fn ntfs_timestamp_bytes() -> [u8; 8] {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ntfs = (unix + 11_644_473_600) * 10_000_000;
    ntfs.to_le_bytes()
}

fn write_ntfs_boot_sector(buf: &mut [u8], mft_cluster: u64) {
    buf[3..11].copy_from_slice(b"NTFS    ");
    buf[11..13].copy_from_slice(&512u16.to_le_bytes());
    buf[13] = 8;
    buf[48..56].copy_from_slice(&mft_cluster.to_le_bytes());
}

fn write_mft_record(buf: &mut [u8], filename: &str, parent: u64, is_directory: bool) {
    buf[0..4].copy_from_slice(b"FILE");
    buf[20..22].copy_from_slice(&56u16.to_le_bytes());
    buf[22..24].copy_from_slice(&1u16.to_le_bytes());

    let t = ntfs_timestamp_bytes();
    let name_utf16: Vec<u16> = filename.encode_utf16().collect();
    let fn_content_len = 66 + name_utf16.len() * 2;
    let fn_attr_len = 24 + fn_content_len;
    let si_len = 72usize;
    let total_attrs = si_len + fn_attr_len + 4;

    let mut pos = 56usize;

    // $STANDARD_INFORMATION
    buf[pos..pos + 4].copy_from_slice(&0x10u32.to_le_bytes());
    buf[pos + 4..pos + 8].copy_from_slice(&(si_len as u32).to_le_bytes());
    buf[pos + 8] = 0;
    buf[pos + 16..pos + 20].copy_from_slice(&48u32.to_le_bytes());
    buf[pos + 20..pos + 22].copy_from_slice(&24u16.to_le_bytes());
    let si = pos + 24;
    buf[si..si + 8].copy_from_slice(&t);
    buf[si + 8..si + 16].copy_from_slice(&t);
    buf[si + 24..si + 32].copy_from_slice(&t);
    pos += si_len;

    // $FILE_NAME
    buf[pos..pos + 4].copy_from_slice(&0x30u32.to_le_bytes());
    buf[pos + 4..pos + 8].copy_from_slice(&(fn_attr_len as u32).to_le_bytes());
    buf[pos + 8] = 0;
    buf[pos + 16..pos + 20].copy_from_slice(&(fn_content_len as u32).to_le_bytes());
    buf[pos + 20..pos + 22].copy_from_slice(&24u16.to_le_bytes());
    let fn_start = pos + 24;
    buf[fn_start..fn_start + 8].copy_from_slice(&parent.to_le_bytes());
    buf[fn_start + 8..fn_start + 16].copy_from_slice(&t);
    buf[fn_start + 16..fn_start + 24].copy_from_slice(&t);
    let flags = if is_directory { 0x1000_0000u32 } else { 0u32 };
    buf[fn_start + 56..fn_start + 60].copy_from_slice(&flags.to_le_bytes());
    buf[fn_start + 64] = name_utf16.len() as u8;
    for (i, ch) in name_utf16.iter().enumerate() {
        let off = fn_start + 66 + i * 2;
        buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
    }
    pos += fn_attr_len;

    buf[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let _ = total_attrs;
}

fn write_ntfs_image(path: &Path, rng: &mut StdRng) {
    const MFT_CLUSTER: u64 = 4;
    const BYTES_PER_SECTOR: u64 = 512;
    const SECTORS_PER_CLUSTER: u64 = 8;
    const MFT_SCAN_RECORDS: u64 = 256;
    let mft_offset = MFT_CLUSTER * SECTORS_PER_CLUSTER * BYTES_PER_SECTOR;
    let record_size = 1024u64;
    // Parser scans 256 consecutive records from mft_offset — image must cover that span.
    let image_size =
        (mft_offset + record_size * MFT_SCAN_RECORDS + rng.gen_range(0u64..8192)) as usize;

    let mut image = vec![0u8; image_size];
    write_ntfs_boot_sector(&mut image[..512], MFT_CLUSTER);

    let records: Vec<(&str, u64, bool)> = vec![
        (".", 5, true),
        ("Windows", 5, true),
        ("Users", 5, true),
        ("Administrator", 5, true),
        ("secret_password.txt", 5, false),
        ("messages.db", 5, false),
        ("BitLockerToGo", 5, true),
    ];

    for (i, (name, parent, is_dir)) in records.iter().enumerate() {
        let off = (mft_offset + record_size * i as u64) as usize;
        if off + record_size as usize <= image.len() {
            write_mft_record(
                &mut image[off..off + record_size as usize],
                name,
                *parent,
                *is_dir,
            );
        }
    }

    // Random padding with JPEG for carving overlap test inside NTFS image
    let jpeg_off = (mft_offset + record_size * 16) as usize;
    if jpeg_off + 4 < image.len() {
        image[jpeg_off..jpeg_off + 3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
    }

    let mut f = std::fs::File::create(path).expect("create ntfs image");
    f.write_all(&image).expect("write ntfs image");
}

fn write_luks_image(path: &Path, rng: &mut StdRng) {
    let mut data = vec![0u8; 65536];
    data[0..6].copy_from_slice(b"LUKS\xba\xbe");
    rng.fill(&mut data[512..]);
    std::fs::write(path, &data).expect("write luks image");
}

fn write_carve_image(path: &Path, rng: &mut StdRng) {
    let mut data = vec![0u8; 256 * 1024];
    rng.fill(&mut data[..]);
    // Embed PNG + PDF + SQLite signatures
    data[4096..4096 + 8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    data[12000..12000 + 4].copy_from_slice(b"%PDF");
    data[24000..24000 + 15].copy_from_slice(b"SQLite format 3");
    std::fs::write(path, &data).expect("write carve image");
}

fn write_sqlite_db(path: &Path, rng: &mut StdRng) {
    let conn = rusqlite::Connection::open(path).expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, message TEXT, timestamp INTEGER);
         CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT);",
    )
    .expect("schema");

    for i in 0..15 {
        let sender = format!("+628{:08}", rng.gen_range(10_000_000..99_999_999));
        let msg = format!("Random forensic message #{i} password token");
        conn.execute(
            "INSERT INTO messages (sender, message, timestamp) VALUES (?1, ?2, ?3)",
            rusqlite::params![sender, msg, 1_700_000_000 + i],
        )
        .expect("insert message");
    }
    conn.execute(
        "INSERT INTO contacts (name, phone) VALUES ('Suspect A', '+62812345678')",
        [],
    )
    .expect("insert contact");
}

fn write_evidence_text(path: &Path, rng: &mut StdRng) {
    let mut lines = vec![
        "CONFIDENTIAL forensic export".into(),
        "user password=RandomP@ss123!".into(),
        "api_token=sk-live-".to_string() + &hex::encode(&rng.gen::<[u8; 8]>()),
    ];
    for i in 0..rng.gen_range(5..20) {
        lines.push(format!("log line {i}: random data {}", rng.gen::<u32>()));
    }
    std::fs::write(path, lines.join("\n")).expect("write evidence");
}

fn write_minimal_png(path: &Path) {
    // Minimal valid 1x1 PNG
    let png: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
        0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
        0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08,
        0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
        0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    std::fs::write(path, png).expect("write png");
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
