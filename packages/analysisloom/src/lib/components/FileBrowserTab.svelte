<script>
  import { invoke } from "@tauri-apps/api/core";
  import FilePreview from "./FilePreview.svelte";
  import SegmentedControl from "./SegmentedControl.svelte";
  import LoadingSkeleton from "./LoadingSkeleton.svelte";
  import { isSqliteArtifact } from "../mftTree.js";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    density,
    onFileSelect,
    onOpenSqlite,
    onMftLoaded,
    imagePath = $bindable(""),
    mftEntries = [],
    filterParent = 5,
    artifactPath = $bindable(""),
    highlightTerm = "",
  } = $props();

  let previewFile = $state(null);
  let previewPath = $state("");
  let sortCol = $state("filename");
  let sortDir = $state("asc");
  let splitRatio = $state(58);
  let viewerMode = $state("preview");

  const modes = [
    { id: "preview", label: "Preview" },
    { id: "hex", label: "Hex" },
    { id: "strings", label: "Strings" },
    { id: "metadata", label: "Metadata" },
  ];

  let entries = $derived(
    mftEntries.filter((e) => (e.parentRecord ?? 0) === (filterParent ?? 5))
  );

  function startDrag(e) {
    const parent = e.target.closest(".workspace-split");
    const startY = e.clientY;
    const startRatio = splitRatio;
    const parentHeight = parent.offsetHeight;

    function onMove(ev) {
      const dy = ev.clientY - startY;
      let newRatio = startRatio + (dy / parentHeight) * 100;
      splitRatio = Math.max(30, Math.min(80, Math.round(newRatio)));
    }
    function onUp() {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    document.body.style.cursor = "ns-resize";
    document.body.style.userSelect = "none";
    e.preventDefault();
  }

  async function recoverDeleted() {
    if (!imagePath) return;
    busy = true;
    try {
      const out = "/tmp/analysisloom_recovered";
      const result = await timeoutPromise(
        invoke("recover_deleted_carve", { imagePath, outputDir: out }),
        120000
      );
      msg = `✅ Recovered ${result.filesFound} deleted/carved files → ${out}`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Recovery",
          filePath: imagePath,
          eventType: `recovered_${result.filesFound}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  export async function loadMft() {
    if (!imagePath) return [];
    busy = true;
    try {
      const result = await timeoutPromise(invoke("parse_mft", { imagePath }), 60000);
      msg = `✅ ${result.length} MFT entries loaded`;
      onMftLoaded?.(result, imagePath);
      if (activeCase?.id) {
        invoke("log_action", { caseId: activeCase.id, action: "LOAD_MFT", detail: imagePath }).catch(() => {});
      }
      return result;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
      return [];
    } finally {
      busy = false;
    }
  }

  function sortBy(col) {
    if (sortCol === col) sortDir = sortDir === "asc" ? "desc" : "asc";
    else { sortCol = col; sortDir = "asc"; }
  }

  let sortedEntries = $derived.by(() => {
    const list = [...entries];
    list.sort((a, b) => {
      let va = a[sortCol], vb = b[sortCol];
      if (typeof va === "string") va = va.toLowerCase();
      if (typeof vb === "string") vb = vb.toLowerCase();
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return list;
  });

  async function selectFile(entry) {
    previewFile = entry.filename || "unnamed";
    const localPath = artifactPath || "";
    previewPath = localPath;

    const baseMeta = {
      size: entry.fileSize,
      modified: entry.siModified || entry.fnModified || "—",
      created: entry.siCreated || entry.fnCreated || "—",
      permissions: entry.isDeleted ? "Deleted" : "Active",
      isDir: !!entry.isDirectory,
      recordNumber: entry.recordNumber,
      parentRecord: entry.parentRecord,
      source: "mft",
    };

    onFileSelect?.(entry.filename || previewFile, baseMeta, localPath || null);

    if (localPath) {
      try {
        const hashes = await invoke("hash_file", { path: localPath });
        onFileSelect?.(localPath, { ...baseMeta, ...hashes, source: "disk" }, localPath);
      } catch {
        /* hash unavailable */
      }
    }

    if (!entry.isDirectory && isSqliteArtifact(entry.filename)) {
      onOpenSqlite?.(entry.filename);
    }
  }

  function onPreviewLoaded(result) {
    if (!result?.metadata) return;
    const path = result.path || previewPath || previewFile;
    onFileSelect?.(path, { ...result.metadata, source: "preview" }, result.path);
  }

  function formatDate(t) {
    if (!t || t === "—") return "—";
    const d = new Date(t);
    if (isNaN(d)) return t.substring(0, 16);
    return `${String(d.getDate()).padStart(2, "0")}/${String(d.getMonth() + 1).padStart(2, "0")}, ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }

  function sizeStr(entry) {
    if (entry?.isDirectory) return "—";
    const s = entry?.fileSize ?? entry;
    if (!s || s === 0) return "0 B";
    if (s < 1024) return `${s} B`;
    const kb = s / 1024;
    if (kb < 1024) return `${Math.round(kb)} KB`;
    return `${(kb / 1024).toFixed(1)} MB`;
  }

  function fileIcon(entry) {
    if (entry.isDeleted) return "❌";
    if (entry.isDirectory) return "📁";
    const n = (entry.filename || "").toLowerCase();
    if (n.endsWith(".sqlite") || n.endsWith(".db")) return "🗄️";
    if (/\.(jpg|jpeg|png|gif|webp)$/.test(n)) return "🖼️";
    return "📄";
  }

  const densityRows = { compact: "24px", standard: "32px", comfortable: "44px" };
  const densityFont = { compact: "11px", standard: "12px", comfortable: "13px" };

  function sortIndicator(col) {
    if (sortCol !== col) return "";
    return sortDir === "asc" ? " ▲" : " ▼";
  }

  $effect(() => {
    if (artifactPath) {
      previewPath = artifactPath;
      previewFile = artifactPath.split(/[/\\]/).pop() || artifactPath;
    }
  });
</script>

<div class="file-browser">
  <div class="load-row">
    <input type="text" bind:value={imagePath} placeholder="/dev/sda or path to E01/DD image..." disabled={busy} />
    <button onclick={() => loadMft()} disabled={busy || !imagePath} class="btn-primary">Load</button>
    {#if mftEntries.some((e) => e.isDeleted)}
      <button onclick={recoverDeleted} disabled={busy || !imagePath} class="btn" title="Carve deleted files from image">Recover Deleted</button>
    {/if}
  </div>

  <div class="workspace-split">
    <div class="list-section" style="flex: 0 0 {splitRatio}%">
      {#if sortedEntries.length}
        <div class="finder-table">
          <div class="thead">
            <button class="th" onclick={() => sortBy("filename")}>Name{sortIndicator("filename")}</button>
            <button class="th" onclick={() => sortBy("siModified")}>Date Modified{sortIndicator("siModified")}</button>
            <button class="th right" onclick={() => sortBy("fileSize")}>Size{sortIndicator("fileSize")}</button>
          </div>
          <div class="tbody">
            {#each sortedEntries.slice(0, 500) as e}
              <button
                class="trow"
                class:deleted={e.isDeleted}
                class:selected={previewFile === e.filename}
                style="height:{densityRows[density] || densityRows.compact};font-size:{densityFont[density] || '12px'}"
                onclick={() => selectFile(e)}
              >
                <span class="col-name">{fileIcon(e)} {e.filename}</span>
                <span class="col-date mono">{formatDate(e.siModified || e.fnModified || e.siCreated)}</span>
                <span class="col-size mono">{sizeStr(e)}</span>
              </button>
            {/each}
          </div>
        </div>
      {:else if busy}
        <div class="loading-panel">
          <LoadingSkeleton rows={8} columns={3} />
          <span class="loading-label"><span class="spinner">⏳</span> Parsing filesystem…</span>
        </div>
      {:else if mftEntries.length}
        <div class="empty">No entries in this folder</div>
      {:else}
        <div class="empty">Add a source image or enter a disk path</div>
      {/if}
    </div>

    {#if previewFile || sortedEntries.length || previewPath}
      <div class="resize-handle" onpointerdown={startDrag} title="Drag to resize" role="separator"></div>
      <div class="viewer-section" style="flex: 0 0 calc(100% - {splitRatio}%)">
        <div class="viewer-toolbar">
          <SegmentedControl options={modes} bind:value={viewerMode} />
          {#if previewFile}<span class="viewer-file mono">{previewFile}</span>{/if}
        </div>
        <div class="viewer-body">
          {#if previewPath}
            <FilePreview
              filePath={previewPath}
              bind:busy
              bind:msg
              {timeoutPromise}
              mode={viewerMode}
              {highlightTerm}
              onPreview={onPreviewLoaded}
            />
          {:else if previewFile}
            <div class="empty small">
              MFT entry — open a carved/local copy to preview &amp; hash
            </div>
          {:else}
            <div class="empty small">Select a file to preview</div>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .file-browser { display: flex; flex-direction: column; height: 100%; padding: 12px 16px; gap: 10px; }
  .load-row { display: flex; gap: 8px; flex-shrink: 0; }
  .load-row input { flex: 1; font-size: 12px; }
  .workspace-split { display: flex; flex-direction: column; flex: 1; min-height: 0; }
  .list-section { overflow: hidden; display: flex; flex-direction: column; min-height: 100px; }
  .finder-table {
    display: flex; flex-direction: column; flex: 1; overflow: auto;
    border: 1px solid var(--divider); border-radius: 8px;
    background: var(--card);
  }
  .thead, .trow {
    display: grid;
    grid-template-columns: minmax(140px, 2fr) minmax(100px, 1fr) minmax(56px, max-content);
    padding: 0 12px; align-items: center; text-align: left; gap: 8px;
  }
  .thead {
    position: sticky; top: 0; z-index: 2;
    background: rgba(0, 0, 0, 0.28); border-bottom: 1px solid var(--divider);
    height: 28px; font-size: 11px; font-weight: 600; color: var(--text-secondary);
  }
  :global(html.theme-light) .thead { background: rgba(255, 255, 255, 0.9); }
  .th { background: none; border: none; color: inherit; cursor: pointer; padding: 0; text-align: left; font: inherit; }
  .th.right { text-align: right; }
  .tbody { overflow-y: auto; }
  .trow {
    width: 100%; border: none; border-bottom: 1px solid var(--divider);
    background: transparent; color: var(--text); cursor: pointer;
  }
  .trow:hover { background: var(--primary-bg); }
  .trow.selected { background: var(--card-active); border-left: 2px solid var(--primary); }
  .trow.deleted { opacity: 0.55; text-decoration: line-through; }
  .col-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .col-date, .col-size { color: var(--text-secondary); }
  .col-size { text-align: right; }
  .mono { font-family: var(--mono); }
  .resize-handle {
    height: 6px; cursor: ns-resize; flex-shrink: 0; margin: 2px 0;
    background: linear-gradient(to bottom, var(--card), rgba(0, 0, 0, 0.35), var(--divider));
    border-radius: 3px; transition: background 0.15s;
  }
  .resize-handle:hover { background: var(--primary); }
  .viewer-section {
    display: flex; flex-direction: column; min-height: 120px;
    border: 1px solid var(--divider); border-radius: 8px;
    background: rgba(0, 0, 0, 0.32);
    overflow: hidden;
    transition: background 0.2s ease, border-color 0.2s ease;
  }
  :global(html.theme-light) .viewer-section { background: rgba(0, 0, 0, 0.04); }
  .viewer-toolbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 10px; flex-shrink: 0; gap: 12px;
    border-bottom: 1px solid var(--divider);
    background: rgba(0, 0, 0, 0.15);
  }
  .loading-panel { padding: 16px; flex: 1; }
  .loading-label { display: block; text-align: center; margin-top: 8px; font-size: 12px; color: var(--text-muted); }
  .viewer-file { font-size: 11px; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; }
  .viewer-body { flex: 1; min-height: 0; overflow: auto; }
  .empty { display: flex; align-items: center; justify-content: center; flex: 1; color: var(--text-muted); font-size: 13px; gap: 6px; }
  .empty.small { min-height: 80px; font-size: 12px; text-align: center; padding: 12px; }
</style>
