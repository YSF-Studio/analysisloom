<script>
  import { invoke } from "@tauri-apps/api/core";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    imagePath = $bindable(""),
    onCountChange,
  } = $props();

  let findings = $state([]);
  let scanned = $state(false);
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Encrypted Volumes",
      hint: "BitLocker · LUKS · VeraCrypt · high-entropy heuristics",
      scan: "Scan Image",
      addSource: "Add a source image to scan for encrypted volumes",
      scanning: "Scanning encryption signatures…",
      none: "No encryption indicators detected in this image",
      prompt: "Run a scan to detect BitLocker, LUKS, VeraCrypt, and high-entropy regions",
      type: "Type",
      location: "Location",
      confidence: "Confidence",
      details: "Details",
      high: "High",
      medium: "Medium",
      low: "Low",
      imagePath: "Disk image from Sources",
    },
    id: {
      title: "Volume Terenkripsi",
      hint: "BitLocker · LUKS · VeraCrypt · heuristik entropi tinggi",
      scan: "Pindai Citra",
      addSource: "Tambahkan citra sumber untuk memindai volume terenkripsi",
      scanning: "Memindai tanda enkripsi…",
      none: "Tidak ada indikator enkripsi terdeteksi pada citra ini",
      prompt: "Jalankan pemindaian untuk mendeteksi BitLocker, LUKS, VeraCrypt, dan region berentropi tinggi",
      type: "Tipe",
      location: "Lokasi",
      confidence: "Keyakinan",
      details: "Detail",
      high: "Tinggi",
      medium: "Sedang",
      low: "Rendah",
      imagePath: "Citra disk dari Sources",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function scan() {
    if (!imagePath) {
      msg = "⚠️ Add a disk image in Sources first";
      findings = [];
      scanned = false;
      onCountChange?.(0);
      return;
    }
    busy = true;
    scanned = true;
    try {
      findings = await timeoutPromise(
        invoke("detect_encrypted", { imagePath }),
        120000
      );
      onCountChange?.(findings.length);
      msg = `✅ ${findings.length} encryption indicator(s) found`;
      if (activeCase?.id) {
        invoke("log_action", {
          caseId: activeCase.id,
          action: "ENCRYPTION_SCAN",
          detail: `${findings.length} findings in ${imagePath}`,
        }).catch(() => {});
        if (findings.length) {
          invoke("record_timeline_event", {
            caseId: activeCase.id,
            timestamp: new Date().toISOString(),
            source: "Encryption",
            filePath: imagePath,
            eventType: `encrypted_${findings.length}`,
          }).catch(() => {});
        }
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
      findings = [];
      onCountChange?.(0);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (!imagePath) {
      findings = [];
      scanned = false;
      onCountChange?.(0);
    }
  });

  function confidenceLabel(c) {
    if (c >= 0.9) return t("high");
    if (c >= 0.7) return t("medium");
    return t("low");
  }

  function confidenceClass(c) {
    if (c >= 0.9) return "pill-high";
    if (c >= 0.7) return "pill-info";
    return "pill-critical";
  }

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="encrypted-panel">
  <div class="header">
    <div>
      <h3>{t("title")}</h3>
      <p class="hint">{t("hint")}</p>
    </div>
    <button class="btn-primary" onclick={scan} disabled={busy || !imagePath}>{t("scan")}</button>
  </div>

  <div class="path-row">
    <input type="text" bind:value={imagePath} placeholder={t("imagePath")} disabled={busy} />
  </div>

  {#if !imagePath}
    <div class="empty">{t("addSource")}</div>
  {:else if busy}
    <div class="empty"><span class="spinner">⏳</span> {t("scanning")}</div>
  {:else if findings.length}
    <div class="findings-list">
      <div class="findings-head">
        <span>{t("type")}</span><span>{t("location")}</span><span>{t("confidence")}</span><span>{t("details")}</span>
      </div>
      {#each findings as f}
        <div class="finding-row">
          <span class="type">🔐 {f.detectionType}</span>
          <span class="mono loc">{f.location}</span>
          <span class="count {confidenceClass(f.confidence)}">{confidenceLabel(f.confidence)} ({Math.round(f.confidence * 100)}%)</span>
          <span class="details">{f.details}{#if f.entropy != null} · H={f.entropy.toFixed(2)}{/if}</span>
        </div>
      {/each}
    </div>
  {:else if scanned}
    <div class="empty">{t("none")}</div>
  {:else}
    <div class="empty">{t("prompt")}</div>
  {/if}
</div>

<style>
  .encrypted-panel { height: 100%; display: flex; flex-direction: column; gap: 10px; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
  h3 { margin: 0 0 4px; font-size: 15px; font-weight: 600; }
  .hint { margin: 0; font-size: 11px; color: var(--text-muted); }
  .path-row input { width: 100%; font-size: 12px; }
  .findings-list {
    flex: 1; min-height: 0; overflow: auto;
    border: 1px solid var(--divider); border-radius: 8px;
  }
  .findings-head, .finding-row {
    display: grid; grid-template-columns: 120px 1fr 120px 2fr;
    gap: 8px; padding: 8px 12px; font-size: 12px;
    border-bottom: 1px solid var(--divider);
  }
  .findings-head {
    position: sticky; top: 0; background: var(--surface-header);
    font-weight: 600; color: var(--text-secondary); font-size: 11px;
  }
  .finding-row:hover { background: var(--primary-bg); }
  .type { font-weight: 600; }
  .mono { font-family: var(--mono); font-size: 11px; }
  .loc { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .details { color: var(--text-secondary); font-size: 11px; }
  .count { font-size: 10px; padding: 2px 8px; border-radius: 10px; font-weight: 600; width: fit-content; }
  .empty {
    display: flex; align-items: center; justify-content: center;
    flex: 1; color: var(--text-muted); font-size: 13px; gap: 8px; padding: 32px;
  }
</style>
