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
  import StatusBar from "./lib/components/StatusBar.svelte";
  import TabBar from "./lib/components/TabBar.svelte";
  import EncryptedTab from "./lib/components/EncryptedTab.svelte";
  import RegistryTab from "./lib/components/RegistryTab.svelte";
  import YaraTab from "./lib/components/YaraTab.svelte";
  import AntiForensicsTab from "./lib/components/AntiForensicsTab.svelte";
  import BrowserTab from "./lib/components/BrowserTab.svelte";
  import NsrlTab from "./lib/components/NsrlTab.svelte";
  import MemoryTab from "./lib/components/MemoryTab.svelte";
  import EvtxTab from "./lib/components/EvtxTab.svelte";
  import MacosTab from "./lib/components/MacosTab.svelte";
  import PcapTab from "./lib/components/PcapTab.svelte";
  import WindowsArtifactsTab from "./lib/components/WindowsArtifactsTab.svelte";
  import SteganographyTab from "./lib/components/SteganographyTab.svelte";
  import EmailTab from "./lib/components/EmailTab.svelte";
  import ChatTab from "./lib/components/ChatTab.svelte";
  import LinuxTab from "./lib/components/LinuxTab.svelte";
  import PluginsTab from "./lib/components/PluginsTab.svelte";
  import { getCurrentWindow } from "@tauri-apps/api/window";
  import { buildMftTree, isSqliteArtifact } from "./lib/mftTree.js";
  import { VIEW_META, DEFAULT_TABS } from "./lib/viewRegistry.js";

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
  let progressStatus = $state("");
  let encryptedCount = $state(0);
  let tabs = $state([...DEFAULT_TABS]);
  let sidebarWidth = $state(220);
  let inspectorWidth = $state(320);
  let theme = $state(import.meta.env.VITE_SCREENSHOT_LIGHT ? "light" : "dark");
  let evidencePaths = $state([]);
  let dragOver = $state(false);
  let integrityStatus = $state(null);

  const caseSealed = $derived(activeCase?.status === "sealed");

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

  async function verifyFileIntegrity(path, sha256) {
    if (!activeCase?.id || !sha256) {
      integrityStatus = null;
      return;
    }
    try {
      integrityStatus = await invoke("verify_evidence_integrity", {
        caseId: activeCase.id,
        filePath: path,
        computedSha256: sha256,
      });
      if (integrityStatus?.expectedSha256 && !integrityStatus.verified) {
        msg = `🔴 INTEGRITY FAIL: ${path.split(/[/\\]/).pop()} — hash does not match manifest`;
      }
    } catch {
      integrityStatus = null;
    }
  }

  async function onFileSelect(path, meta, localPath) {
    selectedFile = localPath || path;
    inspectorMeta = meta ?? null;
    integrityStatus = null;

    if (localPath) {
      hashLoading = true;
      try {
        const hashes = await invoke("hash_file", { path: localPath });
        inspectorMeta = { ...inspectorMeta, ...hashes, source: "disk" };
        await verifyFileIntegrity(localPath, hashes.sha256);
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

    if (activeCase?.id) {
      invoke("record_timeline_event", {
        caseId: activeCase.id,
        timestamp: new Date().toISOString(),
        source: "NTFS",
        filePath: path,
        eventType: `mft_loaded_${entries.length}`,
      }).catch(() => {});
      refreshCaseStats();
    }
  }

  async function refreshCaseStats() {
    if (!activeCase?.id) {
      findingCount = 0;
      bookmarkCount = 0;
      evidencePaths = [];
      return;
    }
    try {
      const stats = await invoke("case_stats", { caseId: activeCase.id });
      findingCount = stats.findingsCount ?? 0;
      bookmarkCount = stats.bookmarkCount ?? 0;
      const evidence = await invoke("list_evidence", { caseId: activeCase.id });
      evidencePaths = evidence.map((e) => e.sourcePath).filter(Boolean);
    } catch {
      /* ignore */
    }
  }

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
    document.documentElement.classList.toggle("theme-light", theme === "light");
  }

  async function handleDroppedPath(path) {
    artifactPath = path;
    selectedFile = path;
    hashLoading = true;
    busy = true;
    try {
      const [hashes, preview] = await Promise.all([
        invoke("hash_file", { path }),
        timeoutPromise(invoke("preview_file", { path }), 30000),
      ]);
      inspectorMeta = { ...preview.metadata, ...hashes, source: "disk" };
      await verifyFileIntegrity(path, hashes.sha256);
      msg = `✅ Dropped: ${path.split(/[/\\]/).pop()}`;
      if (isSqliteArtifact(path)) {
        sqliteDbPath = path;
        activeView = "sqlite";
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    hashLoading = false;
    busy = false;
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

  function bootstrapScreenshotDemo() {
    const imgId = "img-screenshot";
    const path = "/workspace/test-fixtures/random_ntfs.dd";
    const mft = [
      { recordNumber: 0, filename: ".", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
      { recordNumber: 1, filename: "Windows", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
      { recordNumber: 2, filename: "Users", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
      { recordNumber: 3, filename: "Administrator", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
      { recordNumber: 4, filename: "secret_password.txt", parentRecord: 5, isDirectory: false, isDeleted: false, fileSize: 475 },
      { recordNumber: 5, filename: "messages.db", parentRecord: 5, isDirectory: false, isDeleted: false, fileSize: 12288 },
      { recordNumber: 6, filename: "BitLockerToGo", parentRecord: 5, isDirectory: true, isDeleted: false, fileSize: 0 },
    ];
    activeCase = { id: "CASE-A1B2C3", name: "Forensic Demo Case", operator: "Analyst", createdAt: "2026-06-06", status: "active" };
    imagePath = path;
    sqliteDbPath = "/workspace/test-fixtures/messages.db";
    artifactPath = "/workspace/test-fixtures/secret_password_log.txt";
    selectedFile = artifactPath;
    inspectorMeta = {
      size: 475,
      sha256: "a3f2c891d4e5b6071829345fa6678bcde90123456789abcdef0123456789abcd",
      sha1: "b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7",
      md5: "c9d8e7f6a5b4c3d2e1f0091827364554",
      extension: "txt",
      source: "disk",
    };
    mftEntries = mft;
    mftCache = { [imgId]: mft };
    sources = [{
      id: imgId,
      name: "random_ntfs.dd",
      icon: "💽",
      path,
      entryCount: mft.length,
      children: buildMftTree(mft),
    }];
    selectedSource = { id: `${imgId}-root`, imageId: imgId, recordNumber: 5, name: path, isRoot: true };
    fileCount = mft.length;
    findingCount = 1;
    bookmarkCount = 1;
    encryptedCount = 2;
    searchQuery = "password";
    filterParent = 5;
    window.__goToView = setView;
    document.title = "AnalysisLoom — DEMO READY";
  }

  async function loadDemoFixtures(fixtures) {
    busy = true;
    try {
      const c = await invoke("create_case", {
        name: "Forensic Demo Case",
        operator: "Analyst",
      });
      activeCase = c;

      const entries = await timeoutPromise(
        invoke("parse_mft", { imagePath: fixtures.ntfs }),
        120000
      );
      onMftLoaded(entries, fixtures.ntfs);
      imagePath = fixtures.ntfs;

      sqliteDbPath = fixtures.sqlite;

      const [hashes, preview] = await Promise.all([
        invoke("hash_file", { path: fixtures.evidence }),
        timeoutPromise(invoke("preview_file", { path: fixtures.evidence }), 30000),
      ]);
      selectedFile = fixtures.evidence;
      artifactPath = fixtures.evidence;
      inspectorMeta = { ...preview.metadata, ...hashes, source: "disk" };

      await invoke("add_evidence", {
        caseId: c.id,
        sourcePath: fixtures.evidence,
        itemType: "text",
        sha256: hashes.sha256 ?? null,
        sizeBytes: preview.metadata?.size ?? null,
        tag: "high",
        note: "Demo fixture — password log",
      });

      await invoke("record_timeline_event", {
        caseId: c.id,
        timestamp: new Date().toISOString(),
        source: "NTFS",
        filePath: fixtures.ntfs,
        eventType: `mft_loaded_${entries.length}`,
      });

      const enc = await timeoutPromise(
        invoke("detect_encrypted", { imagePath: fixtures.ntfs }),
        120000
      );
      encryptedCount = enc.length;

      await invoke("add_bookmark", {
        caseId: c.id,
        filePath: fixtures.evidence,
        offset: 0,
        tag: "suspicious",
        note: "Contains password keyword",
      });

      searchQuery = "password";
      await refreshCaseStats();
      document.title = "AnalysisLoom — DEMO READY";
    } catch (e) {
      console.error("Demo bootstrap failed:", e);
    }
    busy = false;
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
      await verifyFileIntegrity(picked, hashes.sha256);
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

  async function handleAddEvidence() {
    if (caseSealed) {
      msg = "🔒 Case is sealed — cannot add evidence";
      return;
    }
    if (!selectedFile || !activeCase?.id) {
      msg = "⚠️ Select a case and file first";
      return;
    }
    busy = true;
    try {
      const path = artifactPath || selectedFile;
      const id = await invoke("add_evidence", {
        caseId: activeCase.id,
        sourcePath: path,
        itemType: inspectorMeta?.magicMatch || "artifact",
        sha256: inspectorMeta?.sha256 ?? null,
        sizeBytes: inspectorMeta?.size ?? null,
        tag: inspectorTags.trim() || null,
        note: inspectorNote.trim() || null,
      });
      msg = `✅ Evidence recorded: ${id}`;
      inspectorNote = "";
      inspectorTags = "";
      await refreshCaseStats();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  function openTab(id) {
    const meta = VIEW_META[id];
    if (!meta) return;
    if (!tabs.find((t) => t.id === id)) {
      tabs = [...tabs, { id, icon: meta.icon, label: meta.label }];
    }
    activeView = id;
  }

  function setView(id) {
    openTab(id);
  }

  function startPaneDrag(side, e) {
    const startX = e.clientX;
    const startSidebar = sidebarWidth;
    const startInspector = inspectorWidth;
    function onMove(ev) {
      const dx = ev.clientX - startX;
      if (side === "sidebar") {
        sidebarWidth = Math.max(160, Math.min(400, startSidebar + dx));
      } else {
        inspectorWidth = Math.max(240, Math.min(480, startInspector - dx));
      }
    }
    function onUp() {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    e.preventDefault();
  }

  $effect(() => {
    platform = detectPlatform();
  });

  async function bootstrapScreenshot() {
    if (import.meta.env.VITE_SCREENSHOT_LIGHT) {
      theme = "light";
      document.documentElement.classList.add("theme-light");
    }
    window.__goToView = setView;
    window.__setLightTheme = () => {
      theme = "light";
      document.documentElement.classList.add("theme-light");
    };

    if (import.meta.env.VITE_SCREENSHOT_REAL) {
      const dir = import.meta.env.VITE_FIXTURES_DIR || "/workspace/test-fixtures";
      const fixture = (name) => `${dir}/${name}`;
      try {
        await invoke("nsrl_seed_builtin");
      } catch {
        /* optional */
      }
      await loadDemoFixtures({
        ntfs: fixture("random_ntfs.dd"),
        luks: fixture("luks_volume.dd"),
        carve: fixture("carve_source.dd"),
        sqlite: fixture("messages.db"),
        evidence: fixture("secret_password_log.txt"),
        png: fixture("photo_evidence.png"),
      });
      return;
    }
    bootstrapScreenshotDemo();
  }

  $effect(() => {
    if (import.meta.env.VITE_SCREENSHOT) {
      bootstrapScreenshot();
      return;
    }
    invoke("demo_fixtures")
      .then((fixtures) => {
        if (fixtures) loadDemoFixtures(fixtures);
      })
      .catch(() => {});
  });

  $effect(() => {
    if (import.meta.env.VITE_SCREENSHOT_LIGHT) {
      document.documentElement.classList.add("theme-light");
    }
  });

  $effect(() => {
    if (activeCase?.id) refreshCaseStats();
    else {
      findingCount = 0;
      bookmarkCount = 0;
      evidencePaths = [];
    }
  });

  $effect(() => {
    let unlisten;
    (async () => {
      try {
        const win = getCurrentWindow();
        unlisten = await win.onDragDropEvent((event) => {
          if (event.payload.type === "over") dragOver = true;
          else if (event.payload.type === "leave") dragOver = false;
          else if (event.payload.type === "drop") {
            dragOver = false;
            const p = event.payload.paths?.[0];
            if (p) handleDroppedPath(p);
          }
        });
      } catch {
        /* drag-drop unavailable */
      }
    })();
    return () => { unlisten?.(); };
  });

  async function windowAction(action) {
    const win = getCurrentWindow();
    if (action === "close") await win.close();
    else if (action === "minimize") await win.minimize();
    else if (action === "maximize") await win.toggleMaximize();
  }

  function handleGlobalKeydown(e) {
    const mod = e.metaKey || e.ctrlKey;
    if (!mod) return;
    const key = e.key.toLowerCase();
    if (key === "f") {
      e.preventDefault();
      document.getElementById("global-search")?.focus();
      if (searchQuery.trim()) activeView = "search";
    } else if (key === "b") {
      e.preventDefault();
      setView("bookmarks");
    } else if (key === "n") {
      e.preventDefault();
      setView("cases");
      requestAnimationFrame(() => {
        document.querySelector('.case-panel input[aria-label="Case name"]')?.focus();
      });
    }
  }

  if (import.meta.env.DEV && !import.meta.env.VITE_SCREENSHOT) {
    window.__goToView = setView;
  }
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<div
  class="app-shell platform-{platform}"
  style="--sidebar-w: {sidebarWidth}px; --inspector-w: {inspectorWidth}px"
>
  <header class="titlebar">
    <div class="traffic-lights" aria-hidden="true">
      <button class="tl red" title="Close" aria-label="Close" onclick={() => windowAction("close")}></button>
      <button class="tl yellow" title="Minimize" aria-label="Minimize" onclick={() => windowAction("minimize")}></button>
      <button class="tl green" title="Zoom" aria-label="Zoom" onclick={() => windowAction("maximize")}></button>
    </div>
    <div class="titlebar-brand">
      <img src="/logo.svg" class="title-logo" alt="" />
      <span class="title-text">AnalysisLoom</span>
    </div>
    <div class="titlebar-nav">
      <button class="nav-btn" disabled title="Back" aria-label="Back">‹</button>
      <button class="nav-btn" disabled title="Forward" aria-label="Forward">›</button>
    </div>

    <div class="search-bar">
      <label class="sr-only" for="global-search">Keyword search</label>
      <span class="search-icon" aria-hidden="true">⌕</span>
      <input
        id="global-search"
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
      <button class="title-btn" onclick={toggleTheme} title="Toggle light/dark theme">{theme === "dark" ? "☀" : "☾"}</button>
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

  <TabBar bind:tabs bind:activeView />

  <div class="workspace">
    <aside class="sidebar" role="navigation" aria-label="Sources and views">
      <div class="sidebar-section">
        <div class="section-head">SOURCES</div>
        <button class="nav-item" class:active={activeView === "cases"} onclick={() => setView("cases")}>
          <span>📁</span> Case Manager
        </button>
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
        <button class="nav-item" class:active={activeView === "timeline"} onclick={() => setView("timeline")} aria-current={activeView === "timeline" ? "page" : undefined}>
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
        <div class="section-head">FORENSICS V1.5</div>
        <button class="nav-item" class:active={activeView === "registry"} onclick={() => setView("registry")}>
          <span>📋</span> Registry
        </button>
        <button class="nav-item" class:active={activeView === "yara"} onclick={() => setView("yara")}>
          <span>🦠</span> YARA Scanner
        </button>
        <button class="nav-item" class:active={activeView === "antiforensics"} onclick={() => setView("antiforensics")}>
          <span>🕵️</span> Anti-Forensics
        </button>
        <button class="nav-item" class:active={activeView === "browser"} onclick={() => setView("browser")}>
          <span>🌐</span> Browser Artifacts
        </button>
        <button class="nav-item" class:active={activeView === "nsrl"} onclick={() => setView("nsrl")}>
          <span>📚</span> NSRL Lookup
        </button>
        <button class="nav-item" class:active={activeView === "memory"} onclick={() => setView("memory")}>
          <span>🧠</span> Memory Bridge
        </button>
      </div>

      <div class="sidebar-section">
        <div class="section-head">FORENSICS V2</div>
        <button class="nav-item" class:active={activeView === "evtx"} onclick={() => setView("evtx")}>
          <span>📜</span> Event Log (EVTX)
        </button>
        <button class="nav-item" class:active={activeView === "macos"} onclick={() => setView("macos")}>
          <span>🍎</span> macOS Artifacts
        </button>
        <button class="nav-item" class:active={activeView === "pcap"} onclick={() => setView("pcap")}>
          <span>📡</span> PCAP Network
        </button>
      </div>

      <div class="sidebar-section">
        <div class="section-head">FORENSICS V2.1</div>
        <button class="nav-item" class:active={activeView === "windows"} onclick={() => setView("windows")}>
          <span>🪟</span> Windows Artifacts
        </button>
        <button class="nav-item" class:active={activeView === "stego"} onclick={() => setView("stego")}>
          <span>🖼️</span> Steganography
        </button>
        <button class="nav-item" class:active={activeView === "email"} onclick={() => setView("email")}>
          <span>✉️</span> Email Forensics
        </button>
        <button class="nav-item" class:active={activeView === "chat"} onclick={() => setView("chat")}>
          <span>💬</span> Chat Artifacts
        </button>
        <button class="nav-item" class:active={activeView === "linux"} onclick={() => setView("linux")}>
          <span>🐧</span> Linux Artifacts
        </button>
        <button class="nav-item" class:active={activeView === "plugins"} onclick={() => setView("plugins")}>
          <span>🧩</span> Plugin SDK
        </button>
      </div>

      <div class="sidebar-section">
        <div class="section-head">EVIDENCE</div>
        <button class="nav-item" class:active={activeView === "bookmarks"} onclick={() => setView("bookmarks")}>
          <span>🔖</span> Key Findings {#if findingCount}<span class="count pill-info">{findingCount}</span>{/if}
        </button>
        <button class="nav-item" class:active={activeView === "encrypted"} onclick={() => setView("encrypted")}>
          <span>🔐</span> Encrypted {#if encryptedCount}<span class="count pill-high">{encryptedCount}</span>{/if}
        </button>
        <button class="nav-item" class:active={activeView === "report"} onclick={() => setView("report")}>
          <span>▭</span> Report
        </button>
        <button class="nav-item" class:active={activeView === "about"} onclick={() => setView("about")}>
          <span>ⓘ</span> About
        </button>
      </div>
    </aside>

    <div
      class="pane-resize-v"
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize sidebar"
      onpointerdown={(e) => startPaneDrag("sidebar", e)}
    ></div>

    <main
      class="workspace-main"
      class:padded={activeView !== "files" && activeView !== "sqlite" && activeView !== "encrypted"}
      class:drag-over={dragOver}
    >
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
          highlightTerm={searchQuery}
        />
      {:else if activeView === "timeline"}
        <TimelineTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "carving"}
        <CarvingTab
          bind:activeCase bind:busy bind:msg bind:imagePath
          {timeoutPromise}
          onProgress={(s) => progressStatus = s}
        />
      {:else if activeView === "sqlite"}
        <SqliteTab bind:activeCase bind:busy bind:msg bind:dbPath={sqliteDbPath} {timeoutPromise} />
      {:else if activeView === "search"}
        <SearchTab bind:activeCase bind:busy bind:msg {timeoutPromise} initialQuery={searchQuery} />
      {:else if activeView === "bookmarks"}
        <BookmarkTab bind:activeCase bind:busy bind:msg {timeoutPromise} {caseSealed} />
      {:else if activeView === "encrypted"}
        <EncryptedTab
          bind:activeCase bind:busy bind:msg bind:imagePath
          {timeoutPromise}
          onCountChange={(n) => encryptedCount = n}
        />
      {:else if activeView === "registry"}
        <RegistryTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "yara"}
        <YaraTab bind:activeCase bind:busy bind:msg {timeoutPromise} {evidencePaths} />
      {:else if activeView === "antiforensics"}
        <AntiForensicsTab bind:activeCase bind:busy bind:msg bind:imagePath {timeoutPromise} {evidencePaths} />
      {:else if activeView === "browser"}
        <BrowserTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "nsrl"}
        <NsrlTab bind:busy bind:msg {timeoutPromise} selectedFile={selectedFile || artifactPath || ""} />
      {:else if activeView === "memory"}
        <MemoryTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "evtx"}
        <EvtxTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "macos"}
        <MacosTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "pcap"}
        <PcapTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "windows"}
        <WindowsArtifactsTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "stego"}
        <SteganographyTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "email"}
        <EmailTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "chat"}
        <ChatTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "linux"}
        <LinuxTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "plugins"}
        <PluginsTab bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "report"}
        <ReportTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "about"}
        <DisclaimerTab />
      {/if}
    </main>

    <div
      class="pane-resize-v"
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize inspector"
      onpointerdown={(e) => startPaneDrag("inspector", e)}
    ></div>

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
        {integrityStatus}
        caseId={activeCase?.id}
        selectedFile={artifactPath || selectedFile || ""}
        {caseSealed}
        onAddEvidence={handleAddEvidence}
        onOpenArtifact={onOpenArtifact}
      />
    </aside>
  </div>

  <StatusBar
    {busy}
    {activeCase}
    selectedFile={selectedFile || ""}
    {inspectorMeta}
    {fileCount}
    {findingCount}
    {bookmarkCount}
    {progressStatus}
    tabCount={tabs.length}
    onAuditClick={() => setView("report")}
  />

  {#if msg}
    <div class="toast" role="status" aria-live="polite" class:error={msg.includes("❌")} class:warn={msg.includes("⚠️")}>
      {msg}
      <button class="close-toast" onclick={() => msg = ""}>✕</button>
    </div>
  {/if}
</div>

<style>
  .titlebar-brand {
    display: flex; align-items: center; gap: 8px; margin-right: 8px;
    -webkit-app-region: no-drag;
  }
  .title-logo { width: 18px; height: 18px; border-radius: 4px; }
  .title-text { font-size: 12px; font-weight: 600; color: var(--text-secondary); letter-spacing: -0.2px; }
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
  .traffic-lights .tl {
    width: 12px; height: 12px; border-radius: 50%; border: none; padding: 0; cursor: default;
  }
  .platform-macos .traffic-lights .tl { cursor: pointer; }
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
  .workspace-main.drag-over { outline: 2px dashed var(--primary); outline-offset: -4px; background: var(--primary-bg); }
  .workspace-main > :global(*) {
    flex: 1; min-height: 0; overflow: hidden;
  }
  .workspace-main.padded > :global(*) { overflow: visible; }
  .workspace-main :global(.file-browser),
  .workspace-main :global(.sqlite-manager),
  .workspace-main :global(.encrypted-panel) { height: 100%; }

  .nav-item:disabled { opacity: 0.4; cursor: default; }

  .platform-windows .titlebar,
  .platform-linux .titlebar { padding-left: 16px; }
</style>
