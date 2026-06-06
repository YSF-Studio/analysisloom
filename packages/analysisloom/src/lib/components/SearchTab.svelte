<script>
  import { invoke } from "@tauri-apps/api/core";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
    initialQuery = "",
  } = $props();

  let query = $state("");
  let results = $state([]);
  let searched = $state(false);

  $effect(() => {
    if (initialQuery && initialQuery !== query) {
      query = initialQuery;
      if (activeCase?.id) search();
    }
  });

  async function search() {
    if (!query || !activeCase?.id) return;
    busy = true;
    searched = true;
    try {
      results = await timeoutPromise(
        invoke("keyword_search", { caseId: activeCase.id, query }),
        60000
      );
      msg = `✅ ${results.length} matches found`;
      invoke("log_action", {
        caseId: activeCase.id,
        action: "KEYWORD_SEARCH",
        detail: query,
      }).catch(() => {});
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="search-panel">
  <h3>Keyword Search</h3>
  <p class="hint">Regex-powered search across evidence files in the active case</p>
  <div class="row">
    <label class="sr-only" for="search-query">Search query</label>
    <input
      id="search-query"
      type="search"
      bind:value={query}
      placeholder="password|secret|key|token"
      disabled={busy}
      onkeydown={(e) => e.key === "Enter" && search()}
    />
    <button onclick={search} disabled={busy || !query || !activeCase} class="btn-primary">Search</button>
  </div>
  {#if !activeCase}
    <p class="empty">Open a case to search evidence</p>
  {:else if results.length}
    <div class="results">
      {#each results as r}
        <div class="r">
          <span class="file">{r.filePath}</span>
          <span class="offset">@{r.offset}</span>
          <span class="ctx">{r.context}</span>
        </div>
      {/each}
    </div>
  {:else if searched && !busy}
    <p class="empty">No matches — add evidence files first</p>
  {/if}
</div>

<style>
  .search-panel { height: 100%; }
  h3 { margin: 0 0 4px; font-size: 15px; font-weight: 600; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  .results { margin-top: 12px; font-size: 12px; border: 1px solid var(--divider); border-radius: 8px; overflow: auto; max-height: 60vh; }
  .r { display: grid; grid-template-columns: 1fr auto 2fr; gap: 10px; padding: 8px 12px; border-bottom: 1px solid var(--divider); }
  .r:hover { background: var(--primary-bg); }
  .file { font-weight: 600; overflow: hidden; text-overflow: ellipsis; }
  .offset { color: var(--text-muted); font-family: var(--mono); font-size: 11px; }
  .ctx { color: var(--text-secondary); font-family: var(--mono); font-size: 11px; overflow: hidden; text-overflow: ellipsis; }
  .empty { color: var(--text-muted); font-size: 12px; padding: 16px 0; }
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
</style>
