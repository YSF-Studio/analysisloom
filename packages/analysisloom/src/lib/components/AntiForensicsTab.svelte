<script>
  import { invoke } from "@tauri-apps/api/core";
  import SectionHeader from "./SectionHeader.svelte";
  import SeverityBadge from "./SeverityBadge.svelte";
  import ProgressBar from "./ProgressBar.svelte";
  import LoadingSkeleton from "./LoadingSkeleton.svelte";

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

  async function scanMft() {
    if (!imagePath) {
      msg = "⚠️ Load a disk image first";
      return;
    }
    busy = true;
    scanLabel = "Analyzing MFT for anti-forensics indicators…";
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
      msg = "⚠️ No evidence files in case";
      return;
    }
    busy = true;
    scanLabel = "Scanning evidence files for masquerading…";
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
</script>

<div class="panel">
  <SectionHeader
    title="Anti-Forensics Detection"
    hint="Timestomp · extension mismatch · NTFS ADS · zero-size anomalies · deleted entries"
  />
  <div class="actions">
    <button onclick={scanMft} disabled={busy || !imagePath} class="btn-primary">Scan MFT Image</button>
    <button onclick={scanFiles} disabled={busy || !evidencePaths.length} class="btn">Scan Evidence Files</button>
  </div>

  {#if busy}
    <ProgressBar indeterminate label={scanLabel} />
    <LoadingSkeleton rows={5} columns={3} />
  {:else if findings.length}
    <div class="list">
      <div class="list-head">
        <span>Type</span><span>File</span><span>Details</span><span>Severity</span>
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
    <p class="empty">Detect timestomping, hidden ADS streams, and masqueraded file types</p>
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
    position: sticky; top: 0; background: rgba(0, 0, 0, 0.35);
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
