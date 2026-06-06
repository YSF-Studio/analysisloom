/** View metadata for sidebar navigation and document tabs. */

export const VIEW_META = {
  cases: { icon: "📁", label: "Case Manager" },
  acquisition: { icon: "📦", label: "Acquisition" },
  files: { icon: "▤", label: "NTFS Browser" },
  timeline: { icon: "📊", label: "Timeline" },
  carving: { icon: "🔎", label: "Carved Files" },
  sqlite: { icon: "🗃️", label: "SQLite Manager" },
  search: { icon: "◈", label: "Search" },
  bookmarks: { icon: "🔖", label: "Key Findings" },
  encrypted: { icon: "🔐", label: "Encrypted" },
  registry: { icon: "📋", label: "Registry" },
  yara: { icon: "🦠", label: "YARA Scanner" },
  antiforensics: { icon: "🕵️", label: "Anti-Forensics" },
  browser: { icon: "🌐", label: "Browser Artifacts" },
  nsrl: { icon: "📚", label: "NSRL Lookup" },
  memory: { icon: "🧠", label: "Memory Bridge" },
  evtx: { icon: "📜", label: "Event Log" },
  macos: { icon: "🍎", label: "macOS Artifacts" },
  pcap: { icon: "📡", label: "PCAP Network" },
  windows: { icon: "🪟", label: "Windows Artifacts" },
  stego: { icon: "🖼️", label: "Steganography" },
  email: { icon: "✉️", label: "Email Forensics" },
  chat: { icon: "💬", label: "Chat Artifacts" },
  linux: { icon: "🐧", label: "Linux Artifacts" },
  plugins: { icon: "🧩", label: "Plugin SDK" },
  report: { icon: "▭", label: "Report" },
  about: { icon: "ⓘ", label: "About" },
};

export const DEFAULT_TABS = [{ id: "files", ...VIEW_META.files }];
