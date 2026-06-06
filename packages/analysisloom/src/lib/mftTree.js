/** Build a navigable folder tree from flat NTFS MFT entries. */

const NTFS_ROOT = 5;

export function buildMftTree(entries) {
  const byParent = new Map();
  for (const e of entries) {
    if (!e.isDirectory) continue;
    const parent = e.parentRecord ?? 0;
    if (!byParent.has(parent)) byParent.set(parent, []);
    byParent.get(parent).push(e);
  }

  function branch(parentId) {
    return (byParent.get(parentId) || [])
      .sort((a, b) => (a.filename || "").localeCompare(b.filename || ""))
      .map((e) => ({
        id: `mft-${e.recordNumber}`,
        name: e.filename,
        icon: e.isDeleted ? "🗑️" : "📁",
        recordNumber: e.recordNumber,
        parentRecord: e.parentRecord,
        isDirectory: true,
        children: branch(e.recordNumber),
      }));
  }

  return branch(NTFS_ROOT);
}

export function filterMftEntries(entries, parentRecord) {
  const parent = parentRecord ?? NTFS_ROOT;
  return entries.filter((e) => (e.parentRecord ?? 0) === parent);
}

export function findMftEntry(entries, recordNumber) {
  return entries.find((e) => e.recordNumber === recordNumber) ?? null;
}

export function isSqliteArtifact(filename) {
  const n = (filename || "").toLowerCase();
  return n.endsWith(".sqlite") || n.endsWith(".db") || n.endsWith(".sqlite3");
}
