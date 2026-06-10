<script>
  import { invoke } from "@tauri-apps/api/core";
  import SectionHeader from "./SectionHeader.svelte";
  import SeverityBadge from "./SeverityBadge.svelte";
  import ProgressBar from "./ProgressBar.svelte";
  import LoadingSkeleton from "./LoadingSkeleton.svelte";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    imagePath = $bindable(""),
    evidencePaths = [],
  } = $props();

  let findings = $state([]);
  let scanLabel = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Anti-Forensics Detection",
      hint: "Timestomp · extension mismatch · NTFS ADS · zero-size anomalies · deleted entries",
      loadDisk: "⚠️ Load a disk image first",
      noEvidence: "⚠️ No evidence files in case",
      scanMft: "Scan MFT Image",
      scanFiles: "Scan Evidence Files",
      loading: "Analyzing MFT for anti-forensics indicators…",
      scanning: "Scanning evidence files for masquerading…",
      type: "Type",
      file: "File",
      details: "Details",
      severity: "Severity",
      empty: "Detect timestomping, hidden ADS streams, and masqueraded file types",
    },
    id: {
      title: "Deteksi Anti-Forensik",
      hint: "Timestomp · mismatch ekstensi · NTFS ADS · anomali ukuran nol · entri terhapus",
      loadDisk: "⚠️ Muat citra disk dulu",
      noEvidence: "⚠️ Tidak ada file bukti dalam kasus",
      scanMft: "Pindai Citra MFT",
      scanFiles: "Pindai File Bukti",
      loading: "Menganalisis MFT untuk indikator anti-forensik…",
      scanning: "Memindai file bukti untuk penyamaran…",
      type: "Tipe",
      file: "File",
      details: "Detail",
      severity: "Keparahan",
      empty: "Deteksi timestomping, stream ADS tersembunyi, dan jenis file yang disamarkan",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function scanMft() {
    if (!imagePath) {
      msg = t("loadDisk");
      return;
    }
    busy = true;
    scanLabel = t("loading");
    try {
      findings = await timeoutPromise(invoke("analyze_antiforensics_mft", { imagePath }), 120000);
      msg = `✅ ${findings.length} anti-forensics indicators`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "AntiForensics",
          filePath: imagePath,
          eventType: `antiforensics_${findings.length}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
    scanLabel = "";
  }

  async function scanFiles() {
    if (!evidencePaths.length) {
      msg = t("noEvidence");
      return;
    }
    busy = true;
    scanLabel = t("scanning");
    try {
      findings = await timeoutPromise(
        invoke("analyze_antiforensics_files", { paths: evidencePaths }),
        60000
      );
      msg = `✅ ${findings.length} extension mismatch / masquerading hits`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
    scanLabel = "";
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
  <div class="actions">
    <button onclick={scanMft} disabled={busy || !imagePath} class="btn-primary">{t("scanMft")}</button>
    <button onclick={scanFiles} disabled={busy || !evidencePaths.length} class="btn">{t("scanFiles")}</button>
  </div>

  {#if busy}
    <ProgressBar indeterminate label={scanLabel} />
    <LoadingSkeleton rows={5} columns={3} />
  {:else if findings.length}
    <div class="list">
      <div class="list-head">
        <span>{t("type")}</span><span>{t("file")}</span><span>{t("details")}</span><span>{t("severity")}</span>
      </div>
      {#each findings as f}
        <div class="item">
          <span class="type">{f.detectionType}</span>
          <span class="path" title={f.filePath}>{f.filePath}</span>
          <span class="detail">{f.details}</span>
          <span><SeverityBadge severity={f.severity} /></span>
        </div>
      {/each}
    </div>
  {:else}
    <p class="empty">{t("empty")}</p>
  {/if}
</div>

<style>
  .panel { height: 100%; display: flex; flex-direction: column; }
  .actions { display: flex; gap: 8px; margin-bottom: 12px; flex-shrink: 0; }
  .list {
    border: 1px solid var(--divider); border-radius: 8px; overflow: auto;
    max-height: 65vh; font-size: 12px; flex: 1;
  }
  .list-head, .item {
    display: grid; grid-template-columns: 130px 1fr 1.5fr 110px;
    gap: 8px; padding: 8px 12px; align-items: center;
  }
  .list-head {
    position: sticky; top: 0; background: var(--surface-header);
    font-weight: 600; font-size: 11px; color: var(--text-secondary);
    border-bottom: 1px solid var(--divider);
  }
  .item { border-bottom: 1px solid var(--divider); }
  .item:hover { background: var(--primary-bg); }
  .type { font-weight: 600; font-size: 11px; }
  .path { font-family: var(--mono); font-size: 11px; overflow: hidden; text-overflow: ellipsis; }
  .detail { color: var(--text-secondary); font-size: 11px; }
  .empty { color: var(--text-muted); font-size: 12px; }
</style>
