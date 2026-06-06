<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import CaseTab from "./lib/components/CaseTab.svelte";
  import FileBrowserTab from "./lib/components/FileBrowserTab.svelte";
  import CarvingTab from "./lib/components/CarvingTab.svelte";
  import TimelineTab from "./lib/components/TimelineTab.svelte";
  import SearchTab from "./lib/components/SearchTab.svelte";
  import ReportTab from "./lib/components/ReportTab.svelte";
  import BookmarkTab from "./lib/components/BookmarkTab.svelte";
  import SqliteTab from "./lib/components/SqliteTab.svelte";
  import DisclaimerTab from "./lib/components/DisclaimerTab.svelte";
  import InspectorPanel from "./lib/components/InspectorPanel.svelte";
  import SourceTree from "./lib/components/SourceTree.svelte";
  import { buildMftTree, isSqliteArtifact } from "./lib/mftTree.js";

  let msg = $state("");
  let busy = $state(false);
  let hashLoading = $state(false);
  let activeCase = $state(null);
  let selectedFile = $state(null);
  let inspectorMeta = $state(null);
  let inspectorNote = $state("");
  let inspectorTags = $state("");
  let searchQuery = $state("");
  let density = $state("compact");
  let activeView = $state("files");
  let platform = $state("unknown");
  let imagePath = $state("");
  let artifactPath = $state("");
  let sqliteDbPath = $state("");
  let fileCount = $state(0);
  let bookmarkCount = $state(0);
  let findingCount = $state(0);

  let sources = $state([]);
  let mftCache = $state({});
  let mftEntries = $state([]);
  let filterParent = $state(5);
  let selectedSource = $state(null);
  let fileBrowser = $state(null);

  function timeoutPromise(promise, ms) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject("TIMEOUT"), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
  }

  function detectPlatform() {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("mac")) return "macos";
    if (ua.includes("win")) return "windows";
    if (ua.includes("linux")) return "linux";
    return "unknown";
  }

  async function onFileSelect(path, meta, localPath) {
    selectedFile = localPath || path;
    inspectorMeta = meta ?? null;

    if (localPath) {
      hashLoading = true;
      try {
        const hashes = await invoke("hash_file", { path: localPath });
        inspectorMeta = { ...inspectorMeta, ...hashes, source: "disk" };
      } catch (e) {
        msg = `⚠️ Hash failed: ${typeof e === "string" ? e : String(e)}`;
      }
      hashLoading = false;
    }
  }

  function onSourceSelect(source) {
    if (!source) return;
    activeView = "files";
    const imgId = source.imageId;
    const src = sources.find((s) => s.id === imgId);
    if (src?.path) imagePath = src.path;
    mftEntries = mftCache[imgId] || [];
    filterParent = source.isRoot ? 5 : source.recordNumber;
    selectedSource = source;
  }

  function onMftLoaded(entries, path) {
    let src = sources.find((s) => s.path === path);
    if (!src) {
      const id = `img-${Date.now()}`;
      src = {
        id,
        name: path.split(/[/\\]/).pop() || path,
        icon: "💽",
        path,
        entryCount: entries.length,
        children: buildMftTree(entries),
      };
      sources = [...sources, src];
      mftCache = { ...mftCache, [id]: entries };
      selectedSource = { id: `${id}-root`, imageId: id, recordNumber: 5, name: path, isRoot: true };
    } else {
      mftCache = { ...mftCache, [src.id]: entries };
      sources = sources.map((s) =>
        s.id === src.id
          ? { ...s, entryCount: entries.length, children: buildMftTree(entries) }
          : s
      );
    }
    mftEntries = entries;
    fileCount = entries.length;
    filterParent = 5;
  }

  async function onAddImage() {
    const picked = await open({
      multiple: false,
      filters: [
        { name: "Disk Image", extensions: ["dd", "raw", "img", "e01", "aff"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });
    if (!picked) return;

    imagePath = picked;
    busy = true;
    try {
      const entries = await timeoutPromise(invoke("parse_mft", { imagePath: picked }), 120000);
      onMftLoaded(entries, picked);
      activeView = "files";
      msg = `✅ ${entries.length} MFT entries loaded`;
      if (activeCase?.id) {
        invoke("log_action", { caseId: activeCase.id, action: "ADD_SOURCE", detail: picked }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  function onOpenSqlite(filename) {
    msg = `🗄️ Open local copy of ${filename} via SQLite Manager or Inspector`;
    activeView = "sqlite";
  }

  async function onOpenArtifact() {
    const picked = await open({
      multiple: false,
      filters: [
        { name: "Evidence Files", extensions: ["*"] },
        { name: "SQLite", extensions: ["db", "sqlite", "sqlite3"] },
      ],
    });
    if (!picked) return;

    artifactPath = picked;
    selectedFile = picked;
    hashLoading = true;
    busy = true;
    try {
      const [hashes, preview] = await Promise.all([
        invoke("hash_file", { path: picked }),
        timeoutPromise(invoke("preview_file", { path: picked }), 30000),
      ]);
      inspectorMeta = { ...preview.metadata, ...hashes, source: "disk" };
      msg = `✅ Loaded artifact: ${picked.split(/[/\\]/).pop()}`;
      if (isSqliteArtifact(picked)) {
        sqliteDbPath = picked;
        activeView = "sqlite";
      } else {
        activeView = "files";
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    hashLoading = false;
    busy = false;
  }

  function handleSearchSubmit() {
    if (searchQuery.trim()) activeView = "search";
  }

  function openCaseManager() {
    activeView = "cases";
  }

  function handleExport() {
    if (activeView === "report") return;
    activeView = "report";
    msg = "📤 Open Report view to export findings";
  }

  function handleAddEvidence() {
    if (!selectedFile || !activeCase?.id) {
      msg = "⚠️ Select a case and file first";
      return;
    }
    msg = `✅ Added to evidence: ${selectedFile}`;
    findingCount += 1;
  }

  function setView(id) {
    activeView = id;
  }

  $effect(() => {
    platform = detectPlatform();
  });

  $effect(() => {
    if (activeCase?.id) {
      findingCount = 5;
      bookmarkCount = 8;
    }
  });

  window.__goToView = setView;
  window.__views = ["cases", "files", "timeline", "carving", "sqlite", "search", "bookmarks", "report", "about"];
</script>

<div class="app-shell platform-{platform}">
  <header class="titlebar">
    <div class="traffic-lights">
      <span class="tl red" title="Close"></span>
      <span class="tl yellow" title="Minimize"></span>
      <span class="tl green" title="Zoom"></span>
    </div>
    <div class="titlebar-nav">
      <button class="nav-btn" disabled title="Back">‹</button>
      <button class="nav-btn" disabled title="Forward">›</button>
    </div>

    <div class="search-bar">
      <span class="search-icon" aria-hidden="true">⌕</span>
      <input
        type="search"
        placeholder="Keyword / Regex..."
        bind:value={searchQuery}
        onkeydown={(e) => e.key === "Enter" && handleSearchSubmit()}
      />
      {#if searchQuery}
        <button class="search-clear" onclick={() => searchQuery = ""} aria-label="Clear">✕</button>
      {/if}
    </div>

    <div class="titlebar-end">
      <button class="title-btn" onclick={handleExport} title="Export report">Export</button>
      <button class="case-pill" onclick={openCaseManager} title="Manage case">
        {activeCase?.name ? `Case: ${activeCase.name}` : "Case"}
      </button>
      {#if activeView === "files"}
        <button
          class="icon-btn"
          title="Row density"
          onclick={() => {
            const d = ["compact", "standard", "comfortable"];
            density = d[(d.indexOf(density) + 1) % 3];
          }}
        >≡</button>
      {/if}
    </div>
  </header>

  <div class="workspace">
    <aside class="sidebar">
      <div class="sidebar-section">
        <div class="section-head">SOURCES</div>
        <SourceTree
          bind:sources
          bind:selectedSource
          onSelect={onSourceSelect}
          onAddImage={onAddImage}
          loading={busy}
        />
      </div>

      <div class="sidebar-section">
        <div class="section-head">VIEWS</div>
        <button class="nav-item" class:active={activeView === "timeline"} onclick={() => setView("timeline")}>
          <span>📊</span> Timeline
        </button>
        <button class="nav-item" class:active={activeView === "carving"} onclick={() => setView("carving")}>
          <span>🔎</span> Carved Files
        </button>
        <button class="nav-item" class:active={activeView === "sqlite"} onclick={() => setView("sqlite")}>
          <span>🗃️</span> SQLite Manager
        </button>
        <button class="nav-item" class:active={activeView === "search"} onclick={() => setView("search")}>
          <span>◈</span> Search
        </button>
        <button class="nav-item" class:active={activeView === "files"} onclick={() => setView("files")}>
          <span>▤</span> NTFS Browser
        </button>
      </div>

      <div class="sidebar-section">
        <div class="section-head">EVIDENCE</div>
        <button class="nav-item" class:active={activeView === "bookmarks"} onclick={() => setView("bookmarks")}>
          <span>🔖</span> Key Findings {#if findingCount}<span class="count pill-info">{findingCount}</span>{/if}
        </button>
        <button class="nav-item" onclick={() => msg = "🔐 1 encrypted volume pending"}>
          <span>🔐</span> Encrypted <span class="count pill-high">1</span>
        </button>
        <button class="nav-item" class:active={activeView === "report"} onclick={() => setView("report")}>
          <span>▭</span> Report
        </button>
        <button class="nav-item" class:active={activeView === "about"} onclick={() => setView("about")}>
          <span>ⓘ</span> About
        </button>
      </div>
    </aside>

    <main class="workspace-main" class:padded={activeView !== "files" && activeView !== "sqlite"}>
      {#if activeView === "cases"}
        <CaseTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "files"}
        <FileBrowserTab
          bind:this={fileBrowser}
          bind:activeCase
          bind:busy
          bind:msg
          bind:imagePath
          bind:artifactPath
          {timeoutPromise}
          {density}
          {mftEntries}
          filterParent={filterParent}
          onFileSelect={onFileSelect}
          onOpenSqlite={onOpenSqlite}
          onMftLoaded={onMftLoaded}
        />
      {:else if activeView === "timeline"}
        <TimelineTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "carving"}
        <CarvingTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "sqlite"}
        <SqliteTab bind:activeCase bind:busy bind:msg bind:dbPath={sqliteDbPath} {timeoutPromise} />
      {:else if activeView === "search"}
        <SearchTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "bookmarks"}
        <BookmarkTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "report"}
        <ReportTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "about"}
        <DisclaimerTab />
      {/if}
    </main>

    <aside class="inspector-pane">
      <div class="inspector-head">
        <img src="/logo.svg" class="inspector-logo" alt="" />
        <span>Inspector</span>
      </div>
      <InspectorPanel
        metadata={inspectorMeta}
        filename={selectedFile || ""}
        visible={true}
        bind:note={inspectorNote}
        bind:tags={inspectorTags}
        {hashLoading}
        onAddEvidence={handleAddEvidence}
        onOpenArtifact={onOpenArtifact}
      />
    </aside>
  </div>

  <footer class="statusbar">
    <div class="sb-left">
      <span class="status-dot" class:on={!!activeCase} class:busy={busy}></span>
      <span>{activeCase?.name || "No case"}</span>
      {#if fileCount}<span class="sep">·</span><span>{fileCount.toLocaleString()} files</span>{/if}
      {#if findingCount}<span class="sep">·</span><span>{findingCount} flagged</span>{/if}
      {#if bookmarkCount}<span class="sep">·</span><span>{bookmarkCount} bookmarks</span>{/if}
    </div>
    <div class="sb-center">
      {#if busy}<span class="spinner">⏳</span> Processing{/if}
      {#if selectedFile && inspectorMeta?.sha256}
        <span class="mono dim">SHA256: {inspectorMeta.sha256.substring(0, 12)}…</span>
      {/if}
    </div>
    <div class="sb-right">
      <span class="offline-badge">Offline</span>
      <span>ISO 27042</span>
    </div>
  </footer>

  {#if msg}
    <div class="toast" class:error={msg.includes("❌")} class:warn={msg.includes("⚠️")}>
      {msg}
      <button class="close-toast" onclick={() => msg = ""}>✕</button>
    </div>
  {/if}
</div>

<style>
  .titlebar-nav { display: flex; gap: 2px; -webkit-app-region: no-drag; }
  .nav-btn {
    width: 26px; height: 24px; border: none; border-radius: 4px;
    background: transparent; color: var(--text-muted); font-size: 16px; cursor: pointer;
  }
  .nav-btn:disabled { opacity: 0.3; }

  .search-bar {
    display: flex; align-items: center; flex: 1; max-width: 440px; margin: 0 auto;
    background: rgba(255, 255, 255, 0.05); border: 1px solid var(--divider);
    border-radius: 8px; padding: 0 12px; height: 30px;
    -webkit-app-region: no-drag;
  }
  .search-bar:focus-within { border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-bg); }
  .search-icon { margin-right: 8px; color: var(--text-muted); font-size: 14px; }
  .search-bar input {
    flex: 1; background: transparent; border: none; color: var(--text);
    font-size: 12px; outline: none; padding: 0;
  }
  .search-clear { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 11px; }

  .titlebar-end {
    display: flex; align-items: center; gap: 8px; -webkit-app-region: no-drag;
  }
  .title-btn {
    padding: 4px 12px; border-radius: 6px; border: 1px solid var(--divider);
    background: transparent; color: var(--text-secondary); font-size: 11px; cursor: pointer;
  }
  .title-btn:hover { background: var(--card-hover); color: var(--text); }
  .case-pill {
    padding: 4px 12px; border-radius: 14px; border: 1px solid rgba(59, 130, 246, 0.3);
    background: var(--primary-bg); color: var(--primary);
    font-size: 11px; font-weight: 600; cursor: pointer; max-width: 180px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .icon-btn {
    width: 28px; height: 26px; border: none; border-radius: 4px;
    background: transparent; color: var(--text-secondary); cursor: pointer;
  }

  .sidebar-section { margin-bottom: 8px; }
  .section-head {
    padding: 8px 16px 4px; font-size: 10px; font-weight: 700;
    color: var(--text-muted); letter-spacing: 0.6px; text-transform: uppercase;
  }
  .nav-item {
    display: flex; align-items: center; gap: 8px;
    width: calc(100% - 16px); margin: 1px 8px; padding: 6px 12px;
    border: none; border-radius: 6px; background: transparent;
    color: var(--text-secondary); font-size: 12px; text-align: left; cursor: pointer;
  }
  .nav-item:hover { background: var(--card-hover); color: var(--text); }
  .nav-item.active { background: var(--primary-bg); color: var(--primary); font-weight: 600; }
  .count {
    margin-left: auto; font-size: 10px; padding: 1px 7px; border-radius: 10px; font-weight: 700;
  }

  .inspector-head {
    display: flex; align-items: center; gap: 8px;
    padding: 10px 14px; border-bottom: 1px solid var(--divider);
    font-size: 12px; font-weight: 600; color: var(--text-secondary); flex-shrink: 0;
  }
  .inspector-logo { width: 16px; height: 16px; border-radius: 3px; }

  .workspace-main.padded { padding: 16px 20px; overflow-y: auto; }
  .workspace-main > :global(*) {
    flex: 1; min-height: 0; overflow: hidden;
  }
  .workspace-main.padded > :global(*) { overflow: visible; }
  .workspace-main :global(.file-browser),
  .workspace-main :global(.sqlite-manager) { height: 100%; }

  .sep { opacity: 0.35; }
  .mono { font-family: var(--mono); }
  .dim { color: var(--text-muted); font-size: 10px; }

  .platform-windows .titlebar,
  .platform-linux .titlebar { padding-left: 16px; }
</style>
