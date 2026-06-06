//! Export random forensic fixtures to disk for manual testing.
//! Usage: cargo run --example export_fixtures -- [output_dir] [seed]

use analysisloom_lib::fixtures_gen;
use std::env;
use std::path::PathBuf;

fn main() {
    let out = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../../../test-fixtures"));
    let seed: u64 = env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);

    let ws = fixtures_gen::generate_workspace(seed);
    let dest = out.canonicalize().unwrap_or(out.clone());
    std::fs::create_dir_all(&dest).expect("create output dir");

    for (name, src) in [
        ("random_ntfs.dd", &ws.ntfs_image),
        ("luks_volume.dd", &ws.luks_image),
        ("carve_source.dd", &ws.carve_image),
        ("messages.db", &ws.sqlite_db),
        ("secret_password_log.txt", &ws.evidence_txt),
        ("photo_evidence.png", &ws.evidence_png),
    ] {
        let dst = dest.join(name);
        std::fs::copy(src, &dst).expect("copy fixture");
        println!("  {name} → {}", dst.display());
    }

    fixtures_gen::write_screenshot_extras(&dest);
    println!("  SYSTEM → {}", dest.join("SYSTEM").display());
    println!("  volatility.json → {}", dest.join("volatility.json").display());
    println!("  browser_profile/ → {}", dest.join("browser_profile").display());

    println!("\n✅ Fixtures exported to {} (seed={seed})", dest.display());
    println!("   NTFS image: {}", dest.join("random_ntfs.dd").display());
    println!("   SQLite DB:  {}", dest.join("messages.db").display());
}
