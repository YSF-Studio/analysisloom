<script>
  import CaseTab from "./lib/components/CaseTab.svelte";
  import FileBrowserTab from "./lib/components/FileBrowserTab.svelte";
  import CarvingTab from "./lib/components/CarvingTab.svelte";
  import TimelineTab from "./lib/components/TimelineTab.svelte";
  import SearchTab from "./lib/components/SearchTab.svelte";
  import ReportTab from "./lib/components/ReportTab.svelte";
  import BookmarkTab from "./lib/components/BookmarkTab.svelte";
  import DisclaimerTab from "./lib/components/DisclaimerTab.svelte";
  import InspectorPanel from "./lib/components/InspectorPanel.svelte";

  let msg = $state("");
  let busy = $state(false);
  let activeCase = $state(null);
  let selectedFile = $state(null);
  let inspectorMeta = $state(null);
  let searchQuery = $state("");
  let density = $state("compact");
  let activeView = $state("files");
  let platform = $state("unknown");

  function timeoutPromise(promise, ms) {
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject("TIMEOUT"), ms);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
  }

  const sidebarSections = [
    {
      label: "SOURCES",
      items: [
        { id: "cases", icon: "▣", label: "Case Manager" },
        { id: "files", icon: "▤", label: "File Browser" },
      ]
    },
    {
      label: "VIEWS",
      items: [
        { id: "timeline", icon: "▦", label: "Timeline" },
        { id: "carving", icon: "◎", label: "Carved Files" },
        { id: "search", icon: "◈", label: "Search" },
        { id: "bookmarks", icon: "🔖", label: "Bookmarks" },
        { id: "report", icon: "▭", label: "Report" },
      ]
    },
    {
      label: "INFO",
      items: [
        { id: "about", icon: "ⓘ", label: "About" },
      ]
    }
  ];

  function detectPlatform() {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("mac")) return "macos";
    if (ua.includes("win")) return "windows";
    if (ua.includes("linux")) return "linux";
    return "unknown";
  }

  function onFileSelect(path, meta) {
    selectedFile = path;
    inspectorMeta = meta ?? null;
  }

  function handleSearchSubmit() {
    if (searchQuery.trim()) {
      activeView = "search";
    }
  }

  function clearInspector() {
    selectedFile = null;
    inspectorMeta = null;
  }

  $effect(() => {
    platform = detectPlatform();
  });

  // Screenshot navigation helper
  window.__goToView = (id) => { activeView = id; };
  window.__views = ["cases", "files", "timeline", "carving", "search", "bookmarks", "report", "about"];
</script>

<div class="app-shell platform-{platform}">
  <div class="titlebar">
    <div class="traffic-lights">
      <span class="tl red"></span>
      <span class="tl yellow"></span>
      <span class="tl green"></span>
    </div>
    <div class="titlebar-nav">
      <button class="nav-btn" disabled title="Back">‹</button>
      <button class="nav-btn" disabled title="Forward">›</button>
    </div>
    <img src="/logo.svg" class="logo" alt="AnalysisLoom" />
    <span class="title">AnalysisLoom</span>

    <div class="search-bar">
      <span class="search-icon" aria-hidden="true">⌕</span>
      <input
        type="text"
        placeholder="Keyword / Regex search..."
        bind:value={searchQuery}
        onkeydown={(e) => e.key === "Enter" && handleSearchSubmit()}
      />
      {#if searchQuery}
        <button class="search-clear" onclick={() => searchQuery = ""} aria-label="Clear search">✕</button>
      {/if}
    </div>

    <div class="titlebar-end">
      {#if activeView === "files"}
        <button
          class="toolbar-btn"
          title="Toggle row density"
          onclick={() => {
            const d = ["compact", "standard", "comfortable"];
            density = d[(d.indexOf(density) + 1) % 3];
          }}
        >≡</button>
      {/if}
    </div>
  </div>

  <div class="workspace">
    <aside class="sidebar">
      {#each sidebarSections as section}
        <div class="sidebar-group">
          <span class="sidebar-label">{section.label}</span>
          {#each section.items as item}
            <button
              class="sidebar-item"
              class:active={activeView === item.id}
              onclick={() => activeView = item.id}
            >
              <span class="sidebar-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          {/each}
        </div>
      {/each}
    </aside>

    <div class="workspace-main">
      {#if activeView === "cases"}
        <CaseTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "files"}
        <FileBrowserTab
          bind:activeCase bind:busy bind:msg
          {timeoutPromise} {density} {onFileSelect}
        />
      {:else if activeView === "timeline"}
        <TimelineTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "carving"}
        <CarvingTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "search"}
        <SearchTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "bookmarks"}
        <BookmarkTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "report"}
        <ReportTab bind:activeCase bind:busy bind:msg {timeoutPromise} />
      {:else if activeView === "about"}
        <DisclaimerTab />
      {/if}
    </div>

    {#if inspectorMeta || selectedFile}
      <aside class="inspector-pane">
        <div class="inspector-head">
          <span>Inspector</span>
          <button class="inspector-close" onclick={clearInspector} aria-label="Close inspector">✕</button>
        </div>
        <InspectorPanel metadata={inspectorMeta} visible={true} />
      </aside>
    {/if}
  </div>

  <div class="statusbar">
    <div class="sb-left">
      <span class="status-dot" class:on={!!activeCase} class:busy={busy}></span>
      <span>{activeCase?.name || "AnalysisLoom"}</span>
      {#if selectedFile}
        <span style="opacity:0.35">›</span>
        <span class="file-path" title={selectedFile}>
          {selectedFile.split("/").pop() || selectedFile}
        </span>
      {/if}
    </div>
    <div class="sb-center">
      {#if busy}<span class="spinner">⏳</span> Processing...{/if}
    </div>
    <div class="sb-right">
      <span class="offline-badge">Offline</span>
      <span>ISO 27042</span>
    </div>
  </div>

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
    width: 26px; height: 24px; border: none; border-radius: var(--radius-sm);
    background: transparent; color: var(--text-muted); font-size: 16px; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
  }
  .nav-btn:hover { background: var(--primary-bg); color: var(--text-secondary); }
  .nav-btn:disabled { opacity: 0.3; cursor: default; }

  .search-bar {
    display: flex; align-items: center; flex: 1; max-width: 420px; margin: 0 auto;
    background: rgba(0, 0, 0, 0.25); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 0 10px; height: 30px;
    -webkit-app-region: no-drag;
  }
  .search-bar:focus-within { border-color: var(--primary); }
  .search-icon { font-size: 13px; opacity: 0.5; margin-right: 8px; color: var(--text-secondary); }
  .search-bar input {
    flex: 1; background: transparent; border: none; color: var(--text);
    font-size: 12px; outline: none; padding: 0;
  }
  .search-bar input::placeholder { color: var(--text-muted); }
  .search-clear {
    background: none; border: none; color: var(--text-muted); cursor: pointer;
    font-size: 11px; padding: 2px 4px;
  }
  .search-clear:hover { color: var(--text); }

  .titlebar-end { display: flex; gap: 4px; -webkit-app-region: no-drag; }
  .toolbar-btn {
    width: 28px; height: 26px; border: none; border-radius: var(--radius-sm);
    background: transparent; color: var(--text-secondary); font-size: 14px;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
  }
  .toolbar-btn:hover { background: var(--primary-bg); color: var(--text); }

  .sidebar {
    width: var(--sidebar-w); min-width: var(--sidebar-w);
    background: var(--brand-navy);
    border-right: 1px solid var(--border);
    overflow-y: auto; padding: 8px 0;
  }
  .sidebar-group { margin-bottom: 6px; }
  .sidebar-label {
    display: block; padding: 8px 16px 4px;
    font-size: 10px; font-weight: 700; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.6px;
  }
  .sidebar-item {
    display: flex; align-items: center; gap: 8px;
    width: calc(100% - 16px); padding: 7px 14px; margin: 1px 8px;
    border: none; border-radius: var(--radius);
    background: transparent; color: var(--text-secondary); cursor: pointer;
    font-size: 12px; text-align: left; transition: all 0.12s;
  }
  .sidebar-item:hover { background: var(--card-hover); color: var(--text); }
  .sidebar-item.active {
    background: var(--primary-bg); color: var(--primary); font-weight: 600;
  }
  .sidebar-icon { width: 16px; text-align: center; font-size: 13px; }

  .platform-windows .titlebar,
  .platform-linux .titlebar { padding-left: 16px; }
</style>
