//! Report metadata — tool limitations and disclaimers.

pub const TOOL_LIMITATIONS: &[(&str, &str)] = &[
    (
        "NTFS / MFT Parser",
        "Synthetic NTFS images and standard MFT records. Does not mount live volumes or parse $LogFile/$MFT mirrors.",
    ),
    (
        "Registry Analyzer",
        "Offline hive parsing (SAM, SYSTEM, SOFTWARE, NTUSER.DAT). Complex hive repair and truncated hives may yield partial results.",
    ),
    (
        "YARA Scanner",
        "Built-in rule set plus custom .yar loading. Not a substitute for enterprise YARA-X or sandbox detonation.",
    ),
    (
        "File Carving",
        "Signature-based carving for ~20 common formats. Fragmented or encrypted payloads may not be recovered.",
    ),
    (
        "Browser Artifacts",
        "Chrome, Firefox, Safari, Edge SQLite databases. Encrypted profiles and synced cloud data are out of scope.",
    ),
    (
        "Windows EVTX",
        "Security and operational event logs. Template-dependent fields may be incomplete without vendor manifests.",
    ),
    (
        "macOS Artifacts",
        "KnowledgeC, plist, Unified Log paths. TCC and APFS snapshots require separate acquisition tooling.",
    ),
    (
        "PCAP Analyzer",
        "IPv4 TCP/UDP/DNS flow summary. No full protocol dissection or TLS decryption.",
    ),
    (
        "Memory Bridge",
        "Volatility 3 JSON import only — does not analyze raw memory dumps directly.",
    ),
    (
        "Encryption Detection",
        "Heuristic LUKS/BitLocker/entropy scan. Cannot decrypt or brute-force credentials.",
    ),
    (
        "Windows Artifacts",
        "Prefetch (SCCA), LNK shell links, Jump Lists. Partial OLE parsing; encrypted profiles excluded.",
    ),
    (
        "Steganography Detection",
        "LSB ratio and χ² heuristics on PNG/JPEG. Not a substitute for specialized steganalysis tools.",
    ),
    (
        "Email Forensics",
        "PST/OST header and message stub extraction. Full MAPI/B-tree traversal not implemented.",
    ),
    (
        "Chat Artifacts",
        "WhatsApp, Telegram, Signal SQLite schemas. Encrypted backups and cloud sync out of scope.",
    ),
    (
        "Linux Artifacts",
        "auth.log, audit.log, bash_history text parsing. No live journald or wtmp binary parsing.",
    ),
    (
        "Plugin SDK",
        "Built-in hash, entropy, and strings plugins. Community plugins require future loader integration.",
    ),
    (
        "Cross-Platform Acquisition",
        "Auto-detects Windows/Linux/macOS folder layouts and runs matching analyzers. Extracted trees only — no live APFS/ext4 mount.",
    ),
];

pub fn limitations_html() -> String {
    TOOL_LIMITATIONS
        .iter()
        .map(|(module, limit)| {
            format!(
                "<li><strong>{}</strong> — {}</li>",
                html_escape(module),
                html_escape(limit)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn limitations_text() -> String {
    TOOL_LIMITATIONS
        .iter()
        .map(|(m, l)| format!("{m}: {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
