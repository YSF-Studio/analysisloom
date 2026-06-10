<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { busy = $bindable(), msg = $bindable(), timeoutPromise, selectedFile = "" } = $props();
  let result = $state(null);
  let stats = $state({ hashCount: 0 });
  let importPath = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "NSRL Hash Lookup",
      hint: "Reference library lookup — filter known-good OS files",
      selectFile: "⚠️ Select a file in Inspector or NTFS browser",
      knownGood: "✅ Known-good (NSRL match)",
      unknown: "⚠️ Unknown — requires examination",
      importDone: "✅ Imported",
      seedLoaded: "✅ Built-in NSRL seed loaded",
      lookup: "Lookup Selected File",
      importFile: "Import NSRL File",
      loadSeed: "Load Seed Set",
      status: "Status:",
      nsrlName: "NSRL Name:",
      product: "Product:",
      loaded: "hashes loaded",
    },
    id: {
      title: "Pencarian Hash NSRL",
      hint: "Lookup library referensi — filter file OS yang dikenal baik",
      selectFile: "⚠️ Pilih file di Inspector atau NTFS browser",
      knownGood: "✅ Dikenal baik (cocok NSRL)",
      unknown: "⚠️ Tidak dikenal — perlu pemeriksaan",
      importDone: "✅ Diimpor",
      seedLoaded: "✅ Seed NSRL bawaan dimuat",
      lookup: "Cari File Terpilih",
      importFile: "Impor File NSRL",
      loadSeed: "Muat Seed Set",
      status: "Status:",
      nsrlName: "Nama NSRL:",
      product: "Produk:",
      loaded: "hash dimuat",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function loadStats() {
    try {
      stats = await invoke("nsrl_stats");
    } catch {
      stats = { hashCount: 0 };
    }
  }

  $effect(() => {
    loadStats();
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));

  async function lookupFile() {
    if (!selectedFile) {
      msg = t("selectFile");
      result = null;
      return;
    }
    busy = true;
    try {
      result = await timeoutPromise(invoke("nsrl_lookup_file", { path: selectedFile }), 30000);
      msg = result.knownGood ? t("knownGood") : t("unknown");
    } catch (e) {
      result = null;
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  async function importNsrl() {
    const picked = await open({ multiple: false, filters: [{ name: "NSRL", extensions: ["txt", "csv", "db"] }] });
    if (!picked) return;
    busy = true;
    try {
      const n = await invoke("nsrl_import", { path: picked });
      msg = `✅ ${t("importDone")} ${n} NSRL hashes`;
      await loadStats();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  async function seed() {
    busy = true;
    try {
      await invoke("nsrl_seed_builtin");
      await loadStats();
      msg = t("seedLoaded");
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (!selectedFile) {
      result = null;
    }
  });
</script>

<div class="panel">
  <h3>{t("title")}</h3>
  <p class="hint">{t("hint")} ({stats.hashCount} {t("loaded")})</p>
  <div class="actions">
    <button onclick={lookupFile} disabled={busy || !selectedFile} class="btn-primary">{t("lookup")}</button>
    <button onclick={importNsrl} disabled={busy} class="btn">{t("importFile")}</button>
    <button onclick={seed} disabled={busy} class="btn">{t("loadSeed")}</button>
  </div>
  {#if result}
    <div class="result" class:known={result.knownGood}>
      <p><strong>SHA-256:</strong> <span class="mono">{result.sha256}</span></p>
      <p><strong>{t("status")}</strong> {result.knownGood ? "Known Good ✓" : "Unknown — investigate"}</p>
      {#if result.fileName}<p><strong>{t("nsrlName")}</strong> {result.fileName}</p>{/if}
      {#if result.product}<p><strong>{t("product")}</strong> {result.product}</p>{/if}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .result { padding: 16px; border-radius: 8px; border: 1px solid var(--divider); font-size: 12px; }
  .result.known { border-color: var(--success); background: var(--success-bg); }
  .mono { font-family: var(--mono); font-size: 11px; word-break: break-all; }
</style>
