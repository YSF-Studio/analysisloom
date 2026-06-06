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

export const DEMO_ABOUT = {
  appName: "AnalysisLoom",
  version: "0.1.0",
  developer: "YSF Studio — Built with ❤️ by Yusuf Shalahuddin",
  build: "Master Build — All Features Unlocked",
  features: [
    "Forensic-grade NTFS/MFT Parser & File Browser",
    "File Carving with multi-format signature detection",
    "Timeline Analysis & Event Correlation",
    "SQLite-based Case Management with Audit Trail",
    "Encrypted Volume Detection (LUKS, BitLocker)",
    "100% Offline — Zero Data Collection",
  ],
  disclaimer: "This software is provided 'AS-IS'. Results should be independently verified before use in legal proceedings.",
  offline: true,
  privacy: "100% offline — zero data collection.",
};
