<script>
  import { invoke } from "@tauri-apps/api/core";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    imagePath = $bindable(""),
    onProgress,
  } = $props();

  let outputDir = $state("/tmp/carved");
  let carvedFiles = $state([]);
  let progress = $state({ percent: 0, status: "Idle", isDone: false });
  let pollId = $state(null);

  async function carve() {
    if (!imagePath) return;
    busy = true;
    carvedFiles = [];
    try {
      await timeoutPromise(invoke("start_carving", { imagePath, outputDir }), 5000);
      pollId = setInterval(async () => {
        try {
          const p = await invoke("get_carving_progress");
          progress = p;
          onProgress?.(p.status);
          if (p.isDone) {
            clearInterval(pollId);
            pollId = null;
            const result = await invoke("get_carving_result");
            carvedFiles = result?.files || [];
            busy = false;
            msg = `✅ ${carvedFiles.length} files carved to ${outputDir}`;
            if (activeCase?.id) {
              invoke("record_timeline_event", {
                caseId: activeCase.id,
                timestamp: new Date().toISOString(),
                source: "Carving",
                filePath: imagePath,
                eventType: `carved_${carvedFiles.length}`,
              }).catch(() => {});
              invoke("log_action", {
                caseId: activeCase.id,
                action: "CARVE_COMPLETE",
                detail: `${carvedFiles.length} files`,
              }).catch(() => {});
            }
          }
        } catch {
          clearInterval(pollId);
          pollId = null;
          busy = false;
        }
      }, 500);
    } catch (e) {
      busy = false;
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
  }

  async function cancel() {
    await invoke("cancel_carving");
    if (pollId) clearInterval(pollId);
    pollId = null;
    busy = false;
    onProgress?.("");
  }
</script>

<div class="carving-panel">
  <h3>File Carving</h3>
  <p class="hint">Recover deleted files by magic-byte signature from the active source image</p>
  <div class="row">
    <input type="text" bind:value={imagePath} placeholder="Disk image path (from Sources)" disabled={busy} />
    <input type="text" bind:value={outputDir} placeholder="Output directory" disabled={busy} />
  </div>
  <div class="actions">
    {#if !busy}
      <button onclick={carve} disabled={!imagePath} class="btn-primary">Start Carving</button>
    {:else}
      <button onclick={cancel} class="btn-danger">Stop</button>
    {/if}
  </div>
  {#if progress.percent > 0 || busy}
    <div class="progress-bar" role="progressbar" aria-valuenow={progress.percent} aria-valuemin="0" aria-valuemax="100">
      <div class="fill" style="width:{progress.percent}%"></div>
    </div>
    <p class="info">{progress.status}</p>
  {/if}
  {#if carvedFiles.length}
    <div class="carved-list">
      <div class="carved-head">
        <span>Name</span><span>Type</span><span>Offset</span><span>Size</span>
      </div>
      {#each carvedFiles as f}
        <div class="carved-row">
          <span class="mono">{f.name}</span>
          <span>{f.fileType}</span>
          <span class="mono">0x{f.offset.toString(16)}</span>
          <span class="mono">{f.size.toLocaleString()} B</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .carving-panel { height: 100%; }
  h3 { margin: 0 0 4px; font-size: 15px; font-weight: 600; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 10px; }
  .row input { flex: 1; font-size: 12px; }
  .actions { margin-bottom: 12px; }
  .btn-danger { padding: 8px 16px; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; background: var(--danger); }
  .progress-bar { height: 6px; background: rgba(255,255,255,0.06); border-radius: 4px; margin: 8px 0; overflow: hidden; }
  .fill { height: 100%; background: var(--primary); border-radius: 4px; transition: width 0.3s; }
  .info { font-size: 12px; color: var(--text-secondary); margin: 0 0 12px; }
  .carved-list { border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 50vh; }
  .carved-head, .carved-row {
    display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 8px;
    padding: 8px 12px; font-size: 11px; border-bottom: 1px solid var(--divider);
  }
  .carved-head { position: sticky; top: 0; background: rgba(0,0,0,0.35); font-weight: 600; color: var(--text-secondary); }
  .carved-row:hover { background: var(--primary-bg); }
  .mono { font-family: var(--mono); }
</style>
