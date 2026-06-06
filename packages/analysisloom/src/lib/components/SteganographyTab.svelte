<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let findings = $state([]);
  let paths = $state([]);

  async function scan() {
    const selected = await open({ multiple: true, filters: [{ name: "Images", extensions: ["png", "jpg", "jpeg", "bmp", "gif", "webp"] }] });
    if (!selected) return;
    paths = Array.isArray(selected) ? selected : [selected];
    busy = true;
    try {
      const result = await timeoutPromise(invoke("scan_steganography", { paths }), 120000);
      findings = result.findings;
      msg = `✅ ${result.filesScanned} images scanned, ${result.suspiciousCount} suspicious`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Stego",
          filePath: paths[0] || "",
          eventType: `stego_${result.suspiciousCount}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Steganography Detection</h3>
  <p class="hint">LSB ratio · χ² analysis · metadata anomaly scan on PNG/JPEG/BMP</p>
  <button onclick={scan} disabled={busy} class="btn-primary">Analyze Images</button>
  {#if findings.length}
    <div class="findings">
      {#each findings as f}
        <div class="card" class:suspicious={f.suspicionScore >= 0.6}>
          <div class="head">
            <span class="path">{f.filePath.split("/").pop()}</span>
            <span class="verdict">{f.verdict}</span>
          </div>
          <div class="metrics">
            <span>Format: {f.format}</span>
            <span>LSB: {(f.lsbRatio * 100).toFixed(1)}%</span>
            <span>χ²: {f.chiSquare.toFixed(1)}</span>
            <span>Score: {(f.suspicionScore * 100).toFixed(0)}%</span>
          </div>
          {#if f.metadataAnomalies?.length}
            <ul class="anomalies">
              {#each f.metadataAnomalies as a}<li>{a}</li>{/each}
            </ul>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .findings { margin-top: 12px; display: flex; flex-direction: column; gap: 8px; }
  .card { border: 1px solid var(--divider); border-radius: 8px; padding: 10px; font-size: 11px; }
  .card.suspicious { border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.05); }
  .head { display: flex; justify-content: space-between; margin-bottom: 6px; }
  .path { font-weight: 600; }
  .verdict { color: var(--primary); }
  .metrics { display: flex; gap: 12px; color: var(--text-secondary); flex-wrap: wrap; }
  .anomalies { margin: 6px 0 0; padding-left: 18px; color: var(--text-muted); }
</style>
