<script>
  import { invoke } from "@tauri-apps/api/core";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    imagePath = $bindable(""),
    evidencePaths = [],
  } = $props();

  let findings = $state([]);

  async function scanMft() {
    if (!imagePath) {
      msg = "⚠️ Load a disk image first";
      return;
    }
    busy = true;
    try {
      const mft = await timeoutPromise(invoke("analyze_antiforensics_mft", { imagePath }), 120000);
      findings = mft;
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
  }

  async function scanFiles() {
    if (!evidencePaths.length) {
      msg = "⚠️ No evidence files in case";
      return;
    }
    busy = true;
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
  }
</script>

<div class="panel">
  <h3>Anti-Forensics Detection</h3>
  <p class="hint">Timestomp · extension mismatch · NTFS ADS · zero-size anomalies · deleted entries</p>
  <div class="actions">
    <button onclick={scanMft} disabled={busy || !imagePath} class="btn-primary">Scan MFT Image</button>
    <button onclick={scanFiles} disabled={busy || !evidencePaths.length} class="btn">Scan Evidence Files</button>
  </div>
  {#if findings.length}
    <div class="list">
      {#each findings as f}
        <div class="item sev-{f.severity}">
          <span class="type">{f.detectionType}</span>
          <span class="path">{f.filePath}</span>
          <span class="detail">{f.details}</span>
        </div>
      {/each}
    </div>
  {:else if !busy}
    <p class="empty">Detect timestomping, hidden ADS streams, and masqueraded file types</p>
  {/if}
</div>

<style>
  .panel { height: 100%; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .actions { display: flex; gap: 8px; margin-bottom: 12px; }
  .list { border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 65vh; font-size: 12px; }
  .item { display: grid; grid-template-columns: 140px 1fr 2fr; gap: 8px; padding: 8px 12px; border-bottom: 1px solid var(--divider); }
  .type { font-weight: 600; }
  .path { font-family: var(--mono); font-size: 11px; overflow: hidden; text-overflow: ellipsis; }
  .detail { color: var(--text-secondary); font-size: 11px; }
  .sev-high { background: rgba(239, 68, 68, 0.06); }
  .empty { color: var(--text-muted); }
</style>
