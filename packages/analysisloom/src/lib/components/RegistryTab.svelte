<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import SectionHeader from "./SectionHeader.svelte";
  import ProgressBar from "./ProgressBar.svelte";
  import LoadingSkeleton from "./LoadingSkeleton.svelte";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let hivePath = $state("");
  let scanLabel = $state("");
  let locale = $state(getResolvedLocale());

  const CATEGORY_LABELS = {
    usb: "USB History",
    userassist: "UserAssist / Program Execution",
    shellbags: "Shellbags",
    mru: "MRU / Recent Documents",
    persistence: "Persistence / Autorun",
    mount: "Mounted Volumes",
    profiles: "User Profiles",
    accounts: "Local Accounts",
    other: "Other",
  };

  const TEXT = {
    en: {
      title: "Registry Analyzer",
      hint: "SAM · SYSTEM · SOFTWARE · NTUSER.DAT — USB history, UserAssist, Shellbags, MRU, Run keys",
      browse: "Browse",
      analyze: "Analyze Hive",
      scanFolder: "Scan Folder",
      parsing: "Parsing registry hive…",
      scanning: "Scanning registry folder…",
      keyPath: "Key Path",
      valueName: "Value Name",
      valueData: "Value Data",
      relevance: "Relevance",
      entries: "entries",
      scanned: "keys scanned",
      hivePath: "SYSTEM / NTUSER.DAT path",
    },
    id: {
      title: "Penganalisis Registry",
      hint: "SAM · SYSTEM · SOFTWARE · NTUSER.DAT — histori USB, UserAssist, Shellbags, MRU, Run keys",
      browse: "Jelajah",
      analyze: "Analisis Hive",
      scanFolder: "Pindai Folder",
      parsing: "Mengurai hive registry…",
      scanning: "Memindai folder registry…",
      keyPath: "Jalur Key",
      valueName: "Nama Value",
      valueData: "Data Value",
      relevance: "Relevansi",
      entries: "entri",
      scanned: "key dipindai",
      hivePath: "Path SYSTEM / NTUSER.DAT",
    },
  };

  function t(key) {
    return TEXT[locale]?.[key] || TEXT.en[key] || key;
  }

  function groupFindings(findings) {
    const map = new Map();
    for (const f of findings) {
      const cat = f.category || "other";
      if (!map.has(cat)) map.set(cat, []);
      map.get(cat).push(f);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }

  async function pickHive() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "Registry Hive", extensions: ["dat", "DAT", ""] }],
    });
    if (picked) hivePath = picked;
  }

  async function analyze() {
    if (!hivePath) return;
    busy = true;
    scanLabel = t("parsing");
    try {
      const r = await timeoutPromise(invoke("analyze_registry_hive", { path: hivePath }), 120000);
      results = [r];
      msg = `✅ ${r.findings.length} registry artifacts from ${r.hiveType}`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Registry",
          filePath: hivePath,
          eventType: `registry_${r.findings.length}`,
        }).catch(() => {});
      }
    } catch (e) {
      results = [];
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
      scanLabel = "";
    }
  }

  async function scanDir() {
    const dir = await open({ directory: true });
    if (!dir) return;
    busy = true;
    scanLabel = t("scanning");
    try {
      results = await timeoutPromise(invoke("scan_registry_directory", { dir }), 120000);
      msg = `✅ Scanned ${results.length} hives`;
    } catch (e) {
      results = [];
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
      scanLabel = "";
    }
  }

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="panel">
  <SectionHeader
    title={t("title")}
    hint={t("hint")}
  />
  <div class="row">
    <input type="text" bind:value={hivePath} placeholder={t("hivePath")} disabled={busy} />
    <button onclick={pickHive} disabled={busy} class="btn">{t("browse")}</button>
    <button onclick={analyze} disabled={busy || !hivePath} class="btn-primary">{t("analyze")}</button>
    <button onclick={scanDir} disabled={busy} class="btn">{t("scanFolder")}</button>
  </div>

  {#if busy}
    <ProgressBar indeterminate label={scanLabel || (locale === "id" ? "Menganalisis registry…" : "Analyzing registry…")} />
    <LoadingSkeleton rows={6} columns={3} />
  {/if}

  {#each results as res}
    <div class="hive-block">
      <h4>{res.hiveType} — {res.findings.length} {locale === "id" ? "temuan" : "findings"} ({res.keysScanned} {t("scanned")})</h4>
      {#each groupFindings(res.findings) as [category, items]}
        <section class="category-group">
          <div class="category-head">
            <span class="category-pill">{CATEGORY_LABELS[category] || category}</span>
            <span class="category-count">{items.length} {t("entries")}</span>
          </div>
          <div class="findings-table">
            <div class="findings-head">
              <span>{t("keyPath")}</span>
              <span>{t("valueName")}</span>
              <span>{t("valueData")}</span>
              <span>{t("relevance")}</span>
            </div>
            {#each items as f}
              <div class="finding-row" class:not-found={f.valueData?.includes("not found") || f.valueData?.includes("not present")}>
                <span class="key mono" title={f.keyPath}>{f.keyPath}</span>
                <span class="vname mono">{f.valueName}</span>
                <span class="vdata mono" title={f.valueData}>{f.valueData}</span>
                <span class="rel">{f.forensicRelevance}</span>
              </div>
            {/each}
          </div>
        </section>
      {/each}
    </div>
  {/each}
</div>

<style>
  .panel { height: 100%; display: flex; flex-direction: column; gap: 8px; overflow: hidden; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; flex-shrink: 0; }
  input { flex: 1; min-width: 200px; font-size: 12px; }
  .hive-block {
    flex: 1; min-height: 0; overflow: auto;
    border: 1px solid var(--divider); border-radius: 8px; padding: 10px;
  }
  .hive-block h4 { margin: 0 0 12px; font-size: 13px; color: var(--text-secondary); }
  .category-group { margin-bottom: 16px; }
  .category-head {
    display: flex; align-items: center; gap: 8px; margin-bottom: 6px;
    padding-bottom: 4px; border-bottom: 1px solid var(--divider);
  }
  .category-pill {
    font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 10px;
    background: var(--primary-bg); color: var(--primary);
  }
  .category-count { font-size: 10px; color: var(--text-muted); }
  .findings-table { font-size: 11px; border: 1px solid var(--divider); border-radius: 6px; overflow: hidden; }
  .findings-head, .finding-row {
    display: grid; grid-template-columns: minmax(120px, 1.4fr) minmax(80px, 0.8fr) minmax(100px, 1.2fr) minmax(80px, 0.8fr);
    gap: 8px; padding: 6px 10px; align-items: start;
  }
  .findings-head {
    background: var(--surface-muted); font-weight: 600; font-size: 10px;
    color: var(--text-secondary); text-transform: uppercase;
  }
  .finding-row { border-top: 1px solid var(--divider); }
  .finding-row:hover { background: var(--primary-bg); }
  .finding-row.not-found { opacity: 0.65; }
  .key, .vname, .vdata { overflow: hidden; text-overflow: ellipsis; word-break: break-all; }
  .vdata { color: var(--text); font-weight: 500; }
  .rel { color: var(--text-muted); font-size: 10px; }
  .mono { font-family: var(--mono); }
</style>
