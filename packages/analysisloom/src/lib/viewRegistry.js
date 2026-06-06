/** View metadata for sidebar navigation and document tabs. */

export const VIEW_META = {
  cases: { icon: "📁", label: "Case Manager" },
  files: { icon: "▤", label: "NTFS Browser" },
  timeline: { icon: "📊", label: "Timeline" },
  carving: { icon: "🔎", label: "Carved Files" },
  sqlite: { icon: "🗃️", label: "SQLite Manager" },
  search: { icon: "◈", label: "Search" },
  bookmarks: { icon: "🔖", label: "Key Findings" },
  encrypted: { icon: "🔐", label: "Encrypted" },
  report: { icon: "▭", label: "Report" },
  about: { icon: "ⓘ", label: "About" },
};

export const DEFAULT_TABS = [{ id: "files", ...VIEW_META.files }];
