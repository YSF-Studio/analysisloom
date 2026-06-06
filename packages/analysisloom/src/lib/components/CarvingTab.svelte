<script>
  import { invoke } from "@tauri-apps/api/core";
  import SectionHeader from "./SectionHeader.svelte";
  import ProgressBar from "./ProgressBar.svelte";

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
  <SectionHeader title="File Carving" hint="Recover deleted files by magic-byte signature from the active source image" />
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
    <ProgressBar percent={progress.percent} label={progress.status || "Carving in progress…"} />
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
  .row { display: flex; gap: 8px; margin-bottom: 10px; }
  .row input { flex: 1; font-size: 12px; }
  .actions { margin-bottom: 12px; }
  .btn-danger { padding: 8px 16px; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; background: var(--danger); }
  .carved-list { border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 50vh; }
  .carved-head, .carved-row {
    display: grid; grid-template-columns: 2fr 1fr 1fr 1fr; gap: 8px;
    padding: 8px 12px; font-size: 11px; border-bottom: 1px solid var(--divider);
  }
  .carved-head { position: sticky; top: 0; background: var(--surface-header); font-weight: 600; color: var(--text-secondary); }
  .carved-row:hover { background: var(--primary-bg); }
  .mono { font-family: var(--mono); }
</style>
