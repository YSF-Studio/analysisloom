<script>
  import { invoke } from "@tauri-apps/api/core";

  let { activeCase = $bindable(), busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let cases = $state([]);
  let newCaseName = $state("");
  let operatorName = $state("");

  async function loadCases() {
    busy = true;
    try {
      cases = await timeoutPromise(invoke("list_cases"), 5000);
    } catch (e) {
      /* ignore */
    }
    busy = false;
  }

  async function createCase() {
    if (!newCaseName) return;
    busy = true;
    try {
      const c = await timeoutPromise(
        invoke("create_case", { name: newCaseName, operator: operatorName || "Analyst" }),
        5000
      );
      cases = [c, ...cases];
      activeCase = c;
      newCaseName = "";
      msg = `✅ Case created: ${c.id}`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  function selectCase(c) {
    activeCase = c;
  }

  $effect(() => {
    loadCases();
  });
</script>

<div class="case-panel">
  <h3>Case Management</h3>
  <div class="new-case">
    <input type="text" bind:value={newCaseName} placeholder="Case name..." disabled={busy} aria-label="Case name" />
    <input type="text" bind:value={operatorName} placeholder="Operator name" disabled={busy} aria-label="Operator" />
    <button onclick={createCase} disabled={busy || !newCaseName} class="btn-primary">+ New Case</button>
  </div>
  <div class="case-list">
    {#each cases as c}
      <button
        class="case-card"
        class:active={activeCase?.id === c.id}
        onclick={() => selectCase(c)}
      >
        <strong>{c.name}</strong>
        <span class="meta">{c.id} | {c.createdAt}</span>
        <span class="status" class:sealed={c.status === "sealed"}>{c.status}</span>
      </button>
    {/each}
  </div>
  {#if !cases.length && !busy}
    <p class="empty">No cases yet. Create one to begin forensic analysis.</p>
  {/if}
</div>

<style>
  .case-panel { height: 100%; }
  h3 { margin: 0 0 16px; font-size: 15px; font-weight: 600; }
  .new-case { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .new-case input { flex: 1; min-width: 140px; font-size: 12px; }
  .case-list { display: flex; flex-direction: column; gap: 6px; }
  .case-card {
    padding: 12px; border: 1px solid var(--divider); border-radius: 8px; cursor: pointer;
    display: flex; align-items: center; gap: 12px; background: transparent;
    color: var(--text); text-align: left; width: 100%; font: inherit;
  }
  .case-card:hover { background: var(--card-hover); }
  .case-card.active { border-color: var(--primary); background: var(--primary-bg); }
  .meta { font-size: 11px; color: var(--text-muted); font-family: var(--mono); }
  .status { margin-left: auto; font-size: 10px; padding: 2px 8px; border-radius: 10px; background: var(--success-bg); color: var(--success); text-transform: uppercase; }
  .status.sealed { background: rgba(245,158,11,0.15); color: var(--warn, #f59e0b); }
  .empty { color: var(--text-muted); font-size: 12px; }
</style>
