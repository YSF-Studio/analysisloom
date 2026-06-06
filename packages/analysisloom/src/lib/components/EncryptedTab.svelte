<script>
  import { invoke } from "@tauri-apps/api/core";

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

  async function scan() {
    if (!imagePath) {
      msg = "⚠️ Add a disk image in Sources first";
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
    }
    busy = false;
  }

  function confidenceLabel(c) {
    if (c >= 0.9) return "High";
    if (c >= 0.7) return "Medium";
    return "Low";
  }

  function confidenceClass(c) {
    if (c >= 0.9) return "pill-high";
    if (c >= 0.7) return "pill-info";
    return "pill-critical";
  }
</script>

<div class="encrypted-panel">
  <div class="header">
    <div>
      <h3>Encrypted Volumes</h3>
      <p class="hint">BitLocker · LUKS · VeraCrypt · high-entropy heuristics</p>
    </div>
    <button class="btn-primary" onclick={scan} disabled={busy || !imagePath}>Scan Image</button>
  </div>

  <div class="path-row">
    <input type="text" bind:value={imagePath} placeholder="Disk image from Sources" disabled={busy} />
  </div>

  {#if !imagePath}
    <div class="empty">Add a source image to scan for encrypted volumes</div>
  {:else if busy}
    <div class="empty"><span class="spinner">⏳</span> Scanning encryption signatures…</div>
  {:else if findings.length}
    <div class="findings-list">
      <div class="findings-head">
        <span>Type</span><span>Location</span><span>Confidence</span><span>Details</span>
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
    <div class="empty">No encryption indicators detected in this image</div>
  {:else}
    <div class="empty">Run a scan to detect BitLocker, LUKS, VeraCrypt, and high-entropy regions</div>
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
