<script>
  import { onMount } from "svelte";

  let {
    busy = false,
    activeCase = null,
    selectedFile = "",
    inspectorMeta = null,
    fileCount = 0,
    findingCount = 0,
    bookmarkCount = 0,
    progressStatus = "",
    tabCount = 1,
    locale = "en",
    onAuditClick,
  } = $props();

  let time = $state(new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));

  onMount(() => {
    const id = setInterval(() => {
      time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }, 10000);
    return () => clearInterval(id);
  });

  const text = {
    en: {
      noCase: "No case",
      caseActive: "Case active",
      processing: "Processing",
      tabs: "tabs",
      offline: "Offline",
      audit: "View audit report",
      findings: "findings",
      bookmarks: "bookmarks",
      mft: "MFT",
      statusBar: "Application status",
    },
    id: {
      noCase: "Tidak ada kasus",
      caseActive: "Kasus aktif",
      processing: "Memproses",
      tabs: "tab",
      offline: "Luring",
      audit: "Lihat laporan audit",
      findings: "temuan",
      bookmarks: "bookmark",
      mft: "MFT",
      statusBar: "Status aplikasi",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }
</script>

<footer class="statusbar" aria-label={t("statusBar")}>
  <div class="sb-left">
    <span
      class="status-dot"
      class:on={!!activeCase}
      class:busy={busy}
      aria-label={busy ? t("processing") : activeCase ? t("caseActive") : t("noCase")}
    ></span>
    <span>{activeCase?.name || t("noCase")}</span>
    {#if fileCount}<span class="sep" aria-hidden="true">·</span><span>{fileCount.toLocaleString()} {t("mft")}</span>{/if}
    {#if findingCount}<span class="sep" aria-hidden="true">·</span><span>{findingCount} {t("findings")}</span>{/if}
    {#if bookmarkCount}<span class="sep" aria-hidden="true">·</span><span>{bookmarkCount} {t("bookmarks")}</span>{/if}
  </div>
  <div class="sb-center" aria-live="polite">
    {#if busy && progressStatus}
      <span class="spinner" aria-hidden="true">⏳</span><span>{progressStatus}</span>
    {:else if busy}
      <span class="spinner" aria-hidden="true">⏳</span><span>{t("processing")}</span>
    {:else if selectedFile && inspectorMeta?.sha256}
      <span class="mono dim" title={inspectorMeta.sha256}>SHA256: {inspectorMeta.sha256.substring(0, 16)}…</span>
    {:else if selectedFile}
      <span class="dim truncate" title={selectedFile}>{selectedFile.split(/[/\\]/).pop()}</span>
    {/if}
  </div>
  <div class="sb-right">
    {#if tabCount > 1}<span class="dim">{tabCount} {t("tabs")}</span>{/if}
    <span class="offline-badge">{t("offline")}</span>
    <button
      class="audit-link"
      onclick={() => onAuditClick?.()}
      title={t("audit")}
      disabled={!onAuditClick}
      aria-disabled={!onAuditClick}
    >
      Audit
    </button>
    <span class="time mono">{time}</span>
  </div>
</footer>

<style>
  .statusbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 14px; height: var(--statusbar-h);
    background: var(--surface-statusbar); border-top: 1px solid var(--divider);
    font-size: 11px; color: var(--text-secondary); user-select: none; flex-shrink: 0;
  }
  .sb-left, .sb-center, .sb-right { display: flex; align-items: center; gap: 6px; }
  .sb-center { flex: 1; justify-content: center; min-width: 0; padding: 0 8px; }
  .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 280px; }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%; background: var(--text-muted); flex-shrink: 0;
  }
  .status-dot.on { background: var(--success); box-shadow: 0 0 4px var(--success); }
  .status-dot.busy { background: var(--warn); animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: 0.45; } }
  .sep { opacity: 0.35; }
  .mono { font-family: var(--mono); }
  .dim { color: var(--text-muted); font-size: 10px; }
  .offline-badge {
    padding: 1px 8px; background: var(--success-bg); color: var(--success);
    border-radius: 10px; font-size: 10px; font-weight: 600;
  }
  .audit-link {
    background: none; border: none; color: var(--text-muted); font-size: 10px;
    cursor: pointer; padding: 0 2px;
  }
  .audit-link:hover { color: var(--primary); }
  .audit-link:disabled {
    cursor: default;
    opacity: 0.45;
  }
  .time { min-width: 44px; text-align: right; }
  @media (prefers-reduced-motion: reduce) {
    .status-dot.busy { animation: none; }
    .spinner { animation: none; }
  }
</style>
