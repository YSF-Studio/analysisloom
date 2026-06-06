/** Static demo data for README screenshots (browser-only, no Tauri). */

export const DEMO_CASE = {
  id: "CASE-A1B2C3",
  name: "Forensic Demo Case",
  operator: "Analyst",
  createdAt: "2026-06-06 10:30:00",
  status: "active",
};

export const DEMO_MFT = [
  { recordNumber: 0, filename: ".", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
  { recordNumber: 1, filename: "Windows", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
  { recordNumber: 2, filename: "Users", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
  { recordNumber: 3, filename: "Administrator", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
  { recordNumber: 4, filename: "secret_password.txt", parentRecord: 5, isDirectory: false, isDeleted: false, fileSize: 475 },
  { recordNumber: 5, filename: "messages.db", parentRecord: 5, isDirectory: false, isDeleted: false, fileSize: 12288 },
  { recordNumber: 6, filename: "BitLockerToGo", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
];

export const DEMO_IMAGE = "/workspace/test-fixtures/random_ntfs.dd";

export const DEMO_HASHES = {
  sha256: "a3f2c891d4e5b6071829345fa6678bcde90123456789abcdef0123456789abcd",
  sha1: "b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7",
  md5: "c9d8e7f6a5b4c3d2e1f0091827364554",
};

export const DEMO_TIMELINE = [
  { timestamp: "2026-06-06 10:31:12", eventType: "mft_loaded_7", filePath: DEMO_IMAGE, source: "NTFS" },
  { timestamp: "2026-06-06 10:32:45", eventType: "encrypted_1", filePath: DEMO_IMAGE, source: "Encryption" },
  { timestamp: "2026-06-06 10:33:20", eventType: "carved_10", filePath: DEMO_IMAGE, source: "Carving" },
];

export const DEMO_BOOKMARKS = [
  { id: 1, filePath: "/workspace/test-fixtures/secret_password_log.txt", offset: 0, tag: "suspicious", note: "Contains password keyword", createdAt: "2026-06-06 10:31:00" },
];

export const DEMO_SEARCH = [
  { filePath: "/workspace/test-fixtures/secret_password_log.txt", offset: 42, context: "...user password=RandomP@ss123!..." },
];

export const DEMO_ENCRYPTED = [
  { detectionType: "High Entropy", location: "offset 0x4000", confidence: 0.92, details: "Entropy 7.8 bits/byte", entropy: 7.82 },
  { detectionType: "BitLocker Marker", location: "MFT: BitLockerToGo", confidence: 0.85, details: "Directory name match", entropy: null },
];

export const DEMO_CARVED = [
  { name: "00001000_png.bin", fileType: "PNG", offset: 4096, size: 8192, headerValid: true },
  { name: "00002ee0_pdf.bin", fileType: "PDF", offset: 12000, size: 45000, headerValid: true },
  { name: "00005dc0_sqlite_db.bin", fileType: "SQLite DB", offset: 24000, size: 12288, headerValid: true },
];

export const DEMO_SQLITE_INFO = {
  path: "/workspace/test-fixtures/messages.db",
  tables: ["messages", "contacts"],
  pageSize: 4096,
  pageCount: 3,
};

export const DEMO_SQLITE_COLUMNS = {
  messages: ["id", "sender", "message", "timestamp"],
  contacts: ["id", "name", "phone"],
};

export const DEMO_SQLITE_ROWS = {
  messages: {
    columns: ["id", "sender", "message", "timestamp"],
    rows: [
      ["1", "+62812345678", "Random forensic message #0 password token", "1700000000"],
      ["2", "+62887654321", "Random forensic message #1 password token", "1700000001"],
      ["3", "+62811223344", "Meeting at 14:00 — bring USB", "1700000002"],
    ],
    rowCount: 3,
  },
};

export const DEMO_AUDIT = [
  { timestamp: "2026-06-06 10:31:00", action: "ADD_SOURCE", detail: DEMO_IMAGE },
  { timestamp: "2026-06-06 10:31:15", action: "ENCRYPTION_SCAN", detail: "1 findings" },
  { timestamp: "2026-06-06 10:32:00", action: "KEYWORD_SEARCH", detail: "password" },
];

export const DEMO_REGISTRY = {
  hiveType: "SYSTEM",
  keysScanned: 5,
  findings: [
    { hive: "SYSTEM", keyPath: "ControlSet001\\Enum\\USBSTOR", valueName: "(subkey)", valueData: "Disk&Ven_SanDisk", category: "usb", forensicRelevance: "USB History" },
    { hive: "SYSTEM", keyPath: "ControlSet001\\Enum\\USBSTOR\\4&2a1b3c4d", valueName: "FriendlyName", valueData: "SanDisk Ultra USB 3.0", category: "usb", forensicRelevance: "USB History" },
    { hive: "SOFTWARE", keyPath: "Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist", valueName: "(subkey)", valueData: "{CEBFF5C0}", category: "userassist", forensicRelevance: "UserAssist / Program Execution" },
    { hive: "NTUSER", keyPath: "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", valueName: "(subkey)", valueData: ".txt", category: "mru", forensicRelevance: "Recent Documents (MRU)" },
  ],
};

export const DEMO_YARA = [
  { ruleName: "Suspicious_PowerShell", filePath: "/workspace/test-fixtures/secret_password_log.txt", offset: 128, matchedString: "powershell", matchSnippet: "...invoke-expression powershell -enc SQBFAFgA...", severity: "high" },
  { ruleName: "Ransomware_Note", filePath: "/workspace/test-fixtures/secret_password_log.txt", offset: 0, matchedString: "ransom", matchSnippet: "your files have been encrypted contact support...", severity: "critical" },
];

export const DEMO_ANTIFORENSICS = [
  { detectionType: "Timestomp Suspect", filePath: "/workspace/test-fixtures/random_ntfs.dd::secret_password.txt", severity: "high", details: "$SI created differs from $FN — possible timestomp", recordNumber: 4 },
  { detectionType: "NTFS Alternate Data Stream", filePath: "/workspace/test-fixtures/random_ntfs.dd::zone.identifier:Zone.Identifier", severity: "high", details: "Named data stream 'Zone.Identifier'", recordNumber: 4 },
];

export const DEMO_BROWSER = [
  {
    browser: "Chrome",
    dbPath: "/workspace/test-fixtures/messages.db",
    artifacts: [
      { browser: "Chrome", artifactType: "history", url: "https://mail.google.com", title: "Gmail", visitCount: 42, lastVisit: "2026-06-06 09:15:00 UTC", sourcePath: "" },
      { browser: "Chrome", artifactType: "download", url: "https://cdn.example.com/tool.exe", title: "/Users/Downloads/tool.exe", visitCount: 1, lastVisit: "2026-06-05 14:22:00 UTC", sourcePath: "" },
    ],
  },
];

export const DEMO_NSRL = {
  sha256: DEMO_HASHES.sha256,
  knownGood: false,
  fileName: null,
  product: null,
};

export const DEMO_MEMORY = {
  plugin: "windows.pslist.PsList",
  processes: [
    { pid: 4, name: "System", ppid: 0, cmdline: "", createTime: "2026-06-01 08:00:00" },
    { pid: 512, name: "explorer.exe", ppid: 480, cmdline: "C:\\Windows\\explorer.exe", createTime: "2026-06-01 08:01:12" },
    { pid: 2048, name: "powershell.exe", ppid: 512, cmdline: "powershell -enc SQBFAFgA", createTime: "2026-06-01 09:44:33" },
  ],
  networks: [
    { pid: 2048, protocol: "TCP", localAddr: "192.168.1.10:49152", foreignAddr: "185.220.101.45:443", state: "ESTABLISHED" },
  ],
  rawEntries: 4,
  sourceFile: "/workspace/test-fixtures/volatility.json",
};

export const DEMO_SUPER_TIMELINE = [
  { timestamp: "2026-06-06 10:31:12", source: "NTFS", category: "filesystem", filePath: DEMO_IMAGE, eventType: "mft_loaded_7", severity: "info" },
  { timestamp: "2026-06-06 10:32:00", source: "Registry", category: "registry", filePath: "/evidence/SYSTEM", eventType: "registry_4", severity: "info" },
  { timestamp: "2026-06-06 10:32:45", source: "YARA", category: "malware", filePath: "/workspace/test-fixtures/secret_password_log.txt", eventType: "yara_2", severity: "high" },
  { timestamp: "2026-06-06 10:33:20", source: "Browser", category: "browser", filePath: "/evidence/Chrome/History", eventType: "browser_2", severity: "info" },
];

export const DEMO_EVTX = {
  logPath: "/workspace/test-fixtures/Security.evtx",
  events: [
    { eventId: 4624, timestamp: "2026-06-06T10:00:00Z", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", level: "Info", message: "Administrator | 10.0.0.5", recordId: 1001, forensicRelevance: "Successful Logon" },
    { eventId: 4688, timestamp: "2026-06-06T10:01:00Z", channel: "Security", provider: "Microsoft-Windows-Security-Auditing", level: "Info", message: "powershell.exe", recordId: 1002, forensicRelevance: "Process Creation" },
    { eventId: 4104, timestamp: "2026-06-06T10:02:00Z", channel: "Microsoft-Windows-PowerShell/Operational", provider: "PowerShell", level: "Info", message: "Invoke-Expression", recordId: 1003, forensicRelevance: "PowerShell Script Block" },
  ],
  recordsParsed: 3,
  channel: "Security",
};

export const DEMO_MACOS = [
  {
    sourcePath: "/workspace/test-fixtures/macos_profile/Library/Application Support/KnowledgeC.db",
    artifacts: [
      { artifactType: "user_activity", path: "/workspace/test-fixtures/macos_profile/Library/Application Support/KnowledgeC.db", key: "738000.0", value: "/Applications/Safari.app", timestamp: "2026-06-06T10:00:00Z", category: "knowledgec", forensicRelevance: "KnowledgeC — user activity timeline" },
      { artifactType: "plist", path: "/workspace/test-fixtures/macos_profile/Library/Preferences/com.apple.loginwindow.plist", key: "lastUserName", value: "forensic_analyst", timestamp: "2026-06-06T10:00:00Z", category: "login", forensicRelevance: "macOS Preferences plist" },
    ],
    sourcesScanned: 2,
  },
];

export const DEMO_PCAP = {
  filePath: "/workspace/test-fixtures/capture.pcap",
  flows: [
    { protocol: "TCP", srcIp: "192.168.1.10", dstIp: "185.220.101.45", srcPort: 49168, dstPort: 443, packetCount: 1, bytes: 54, firstSeen: "1700000000.000000", lastSeen: "1700000000.000000", info: "HTTPS/TLS" },
  ],
  packetsParsed: 1,
  durationSecs: 0,
};

export const DEMO_WINDOWS = {
  artifacts: [
    { artifactType: "prefetch", name: "NOTEPAD.EXE-ABC123.pf", sourcePath: "/workspace/test-fixtures/Windows/Prefetch/NOTEPAD.EXE-ABC123.pf", executable: "NOTEPAD.EXE", targetPath: "", runCount: 12, lastRun: "2026-06-06T10:00:00Z", details: "SCCA v30, run_count=12" },
    { artifactType: "lnk", name: "notepad.lnk", sourcePath: "/workspace/test-fixtures/recent/notepad.lnk", executable: "", targetPath: "C:\\Windows\\System32\\notepad.exe", runCount: 0, lastRun: "—", details: "link_flags=0x00000002" },
  ],
  prefetchCount: 1,
  lnkCount: 1,
  jumpListCount: 0,
};

export const DEMO_STEGO = {
  findings: [
    { filePath: "/workspace/test-fixtures/stego_sample.png", format: "PNG", lsbRatio: 0.62, chiSquare: 85.2, suspicionScore: 0.72, verdict: "high — possible hidden data", metadataAnomalies: ["Embedded keyword 'hidden' in file bytes"], details: "LSB ratio=0.620, χ²=85.2, score=0.72" },
  ],
  filesScanned: 1,
  suspiciousCount: 1,
};

export const DEMO_EMAIL = [
  {
    filePath: "/workspace/test-fixtures/mailbox.pst",
    mailboxType: "PST (ANSI)",
    version: 23,
    encrypted: false,
    messageCount: 1,
    messages: [{ subject: "Quarterly Report Review", sender: "cfo@corp.example.com", recipients: "analyst@corp.example.com", sentTime: "2026-06-01", folder: "Inbox", bodyPreview: "Please review attached financials." }],
    folders: ["Inbox", "Sent Items"],
    details: "Parsed 1 message stubs, 2 folders, encrypted=false",
  },
];

export const DEMO_CHAT = [
  {
    platform: "WhatsApp",
    dbPath: "/workspace/test-fixtures/whatsapp/msgstore.db",
    messageCount: 1,
    messages: [{ platform: "WhatsApp", chatId: "1234567890@s.whatsapp.net", sender: "+1234567890", message: "Meeting moved to 3pm — confirm attendance", timestamp: "2023-11-14T22:13:20Z", messageType: "type_0" }],
  },
];

export const DEMO_LINUX = {
  events: [
    { eventType: "auth_success", timestamp: "Jun  6 10:15:01", user: "analyst", source: "192.168.1.50", command: "", details: "Accepted password for analyst from 192.168.1.50", sourceFile: "/workspace/test-fixtures/linux_logs/auth.log" },
    { eventType: "bash_history", timestamp: "#0", user: "—", source: "", command: "sudo cat /etc/passwd", details: "Shell command history entry", sourceFile: "/workspace/test-fixtures/linux_logs/.bash_history" },
  ],
  authEvents: 1,
  auditEvents: 0,
  historyCommands: 1,
  filesParsed: 2,
};

export const DEMO_PLUGINS = [
  { id: "hash-file", name: "File Hasher", version: "1.0.0", description: "Compute SHA-256, SHA-1, and MD5 hashes for any file", supportedExtensions: ["*"], builtin: true },
  { id: "entropy-scan", name: "Entropy Scanner", version: "1.0.0", description: "Measure byte-level Shannon entropy", supportedExtensions: ["*"], builtin: true },
  { id: "strings-extract", name: "Strings Extractor", version: "1.0.0", description: "Extract printable ASCII strings from binary files", supportedExtensions: ["*"], builtin: true },
];

export const DEMO_ABOUT = {
  appName: "AnalysisLoom",
  version: "0.1.0",
  developer: "YSF Studio — Built with ❤️ by Yusuf Shalahuddin",
  build: "V2 Forensic Workstation — All Features Unlocked",
  features: [
    "Forensic-grade NTFS/MFT Parser & File Browser",
    "File Carving with multi-format signature detection",
    "Super Timeline — multi-source event correlation",
    "Registry Analyzer (SAM / SYSTEM / SOFTWARE / NTUSER.DAT)",
    "Built-in YARA Scanner with custom .yar rule loading",
    "Anti-Forensics Detection (timestomp, ADS, extension mismatch)",
    "Browser Artifacts (Chrome, Firefox, Safari, Edge)",
    "NSRL Known-Good Hash Lookup",
    "Memory Analysis Bridge (Volatility 3 JSON import)",
    "Hex & Keyword Search across case evidence",
    "SQLite Artifact Browser & Case Management with Audit Trail",
    "Encrypted Volume Detection (LUKS, BitLocker, high-entropy)",
    "100% Offline — Zero Data Collection",
  ],
  disclaimer: "This software is provided 'AS-IS'. Results should be independently verified before use in legal proceedings.",
  offline: true,
  privacy: "100% offline — zero data collection.",
};
