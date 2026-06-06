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
      result = await timeoutPromise(invoke("scan_linux_artifacts", { root: rootPath }), 120000);
      msg = `✅ ${result.events.length} events (${result.authEvents} auth, ${result.auditEvents} audit, ${result.historyCommands} history)`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Linux",
          filePath: rootPath,
          eventType: `linux_${result.events.length}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Linux Artifacts</h3>
  <p class="hint">auth.log · audit.log · .bash_history — endpoint activity traces</p>
  <div class="row">
    <input type="text" bind:value={rootPath} placeholder="/var/log or evidence folder" disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">Scan Linux Logs</button>
  </div>
  {#if result}
    <div class="stats">
      <span>Files: {result.filesParsed}</span>
      <span>Auth: {result.authEvents}</span>
      <span>Audit: {result.auditEvents}</span>
      <span>History: {result.historyCommands}</span>
    </div>
    <div class="events">
      <div class="thead"><span>Type</span><span>Time</span><span>User</span><span>Command / Details</span></div>
      {#each result.events.slice(0, 150) as ev}
        <div class="ev type-{ev.eventType}">
          <span class="type">{ev.eventType}</span>
          <span class="ts">{ev.timestamp}</span>
          <span class="user">{ev.user}</span>
          <span class="cmd">{ev.command || ev.details}</span>
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
  .events { font-size: 11px; border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 70vh; }
  .thead, .ev { display: grid; grid-template-columns: 100px 100px 80px 1fr; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--divider); }
  .thead { font-weight: 600; color: var(--text-secondary); position: sticky; top: 0; background: rgba(0,0,0,0.4); }
  .type { font-weight: 600; font-size: 10px; text-transform: uppercase; }
  .type-auth_failure { background: rgba(239, 68, 68, 0.05); }
  .cmd { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); }
</style>
