<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let result = $state(null);
  let rootPath = $state("");

  async function scan() {
    const root = rootPath || (await open({ directory: true }));
    if (!root) return;
    rootPath = typeof root === "string" ? root : rootPath;
    busy = true;
    try {
      result = await timeoutPromise(invoke("scan_windows_artifacts", { root: rootPath }), 120000);
      msg = `✅ ${result.artifacts.length} artifacts (${result.prefetchCount} prefetch, ${result.lnkCount} LNK, ${result.jumpListCount} jump lists)`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Windows",
          filePath: rootPath,
          eventType: `windows_${result.artifacts.length}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Windows Artifacts</h3>
  <p class="hint">Prefetch (SCCA) · Shell Links (LNK) · Jump Lists (AutomaticDestinations-ms)</p>
  <div class="row">
    <input type="text" bind:value={rootPath} placeholder="C:\Windows\Prefetch or evidence folder" disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">Scan Windows Artifacts</button>
  </div>
  {#if result}
    <div class="stats">
      <span>Prefetch: {result.prefetchCount}</span>
      <span>LNK: {result.lnkCount}</span>
      <span>Jump Lists: {result.jumpListCount}</span>
    </div>
    <div class="artifacts">
      {#each result.artifacts.slice(0, 100) as art}
        <div class="art">
          <span class="type">{art.artifactType}</span>
          <span class="name">{art.name}</span>
          <span class="exec">{art.executable || art.targetPath || "—"}</span>
          <span class="meta">{art.runCount ? `${art.runCount}×` : ""} {art.lastRun}</span>
          <span class="details">{art.details}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  .stats { display: flex; gap: 16px; font-size: 11px; color: var(--text-secondary); margin-bottom: 8px; }
  .art { display: grid; grid-template-columns: 70px 1fr 1.5fr auto; gap: 8px; font-size: 11px; padding: 5px 0; border-bottom: 1px solid var(--divider); }
  .type { font-weight: 600; color: var(--primary); text-transform: uppercase; font-size: 10px; }
  .exec { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; }
  .meta { color: var(--text-muted); white-space: nowrap; }
  .details { grid-column: 1 / -1; color: var(--text-muted); font-size: 10px; }
</style>
