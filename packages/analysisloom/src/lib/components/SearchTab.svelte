<script>
  import { invoke } from "@tauri-apps/api/core";
  import { highlightSegments } from "../highlight.js";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

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
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Search",
      hint: "Keyword/regex or hex byte patterns — prefix hex with hex: (e.g. hex:FF D8 FF)",
      query: "Search query",
      search: "Search",
      openCase: "Open a case to search evidence",
      noMatches: "No matches — add evidence files first",
      queryExample: "password | hex:FF D8 FF | 504B0304",
    },
    id: {
      title: "Pencarian",
      hint: "Kata kunci/regex atau pola byte hex — awali hex dengan hex: (mis. hex:FF D8 FF)",
      query: "Kueri pencarian",
      search: "Cari",
      openCase: "Buka kasus untuk mencari bukti",
      noMatches: "Tidak ada hasil — tambahkan file bukti dulu",
      queryExample: "password | hex:FF D8 FF | 504B0304",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  $effect(() => {
    if (!activeCase?.id) {
      results = [];
      searched = false;
      return;
    }
    if (initialQuery && initialQuery !== query) {
      query = initialQuery;
      if (activeCase?.id) search();
    }
  });

  async function search() {
    if (!query || !activeCase?.id) {
      results = [];
      searched = false;
      return;
    }
    busy = true;
    searched = true;
    try {
      results = await timeoutPromise(
        invoke("unified_search", { caseId: activeCase.id, query }),
        60000
      );
      msg = `✅ ${results.length} matches found`;
      invoke("log_action", {
        caseId: activeCase.id,
        action: "KEYWORD_SEARCH",
        detail: query,
      }).catch(() => {});
    } catch (e) {
      results = [];
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (!activeCase?.id) {
      results = [];
      searched = false;
    }
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="search-panel">
  <h3>{t("title")}</h3>
  <p class="hint">{t("hint")}</p>
  <div class="row">
    <label class="sr-only" for="search-query">{t("query")}</label>
    <input
      id="search-query"
      type="search"
      bind:value={query}
      placeholder={t("queryExample")}
      disabled={busy}
      onkeydown={(e) => e.key === "Enter" && search()}
    />
    <button onclick={search} disabled={busy || !query || !activeCase} class="btn-primary">{t("search")}</button>
  </div>
  {#if !activeCase}
    <p class="empty">{t("openCase")}</p>
  {:else if results.length}
    <div class="results">
      {#each results as r}
        <div class="r">
          <span class="file">{r.filePath}</span>
          <span class="offset">@{r.offset}</span>
          <span class="ctx">{#each highlightSegments(r.context, query) as seg}{#if seg.match}<mark class="hl">{seg.text}</mark>{:else}{seg.text}{/if}{/each}</span>
        </div>
      {/each}
    </div>
  {:else if searched && !busy}
    <p class="empty">{t("noMatches")}</p>
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
  mark.hl { background: var(--mark-bg); color: var(--text-highlight); padding: 0 1px; border-radius: 2px; }
  .empty { color: var(--text-muted); font-size: 12px; padding: 16px 0; }
  .sr-only {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0;
  }
</style>
