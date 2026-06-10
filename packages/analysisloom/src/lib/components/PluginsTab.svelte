<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let plugins = $state([]);
  let selected = $state(null);
  let filePath = $state("");
  let runResult = $state(null);
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Plugin SDK",
      hint: "Built-in forensic plugins — extensible Rust trait interface",
      available: "plugins available",
      run: "Run:",
      target: "Target file path",
      runPlugin: "Run Plugin",
      noPlugin: "No plugins found",
      pickPlugin: "Select a plugin to see details and run it",
      noOutput: "Plugin completed without structured output",
      completed: "completed",
    },
    id: {
      title: "SDK Plugin",
      hint: "Plugin forensik bawaan — antarmuka trait Rust yang dapat diperluas",
      available: "plugin tersedia",
      run: "Jalankan:",
      target: "Jalur file target",
      runPlugin: "Jalankan Plugin",
      noPlugin: "Tidak ada plugin ditemukan",
      pickPlugin: "Pilih plugin untuk melihat detail dan menjalankannya",
      noOutput: "Plugin selesai tanpa output terstruktur",
      completed: "selesai",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function loadPlugins() {
    busy = true;
    try {
      plugins = await timeoutPromise(invoke("list_forensic_plugins"), 10000);
      if (!plugins.length) {
        selected = null;
        runResult = null;
      } else if (!selected || !plugins.some((p) => p.id === selected.id)) {
        selected = plugins[0];
      }
      msg = `✅ ${plugins.length} ${t("available")}`;
    } catch (e) {
      plugins = [];
      selected = null;
      runResult = null;
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function runPlugin() {
    if (!selected) return;
    const path = filePath || (await open());
    if (!path) return;
    filePath = typeof path === "string" ? path : filePath;
    busy = true;
    try {
      runResult = await timeoutPromise(invoke("run_forensic_plugin", { pluginId: selected.id, path: filePath }), 60000);
      msg = runResult.success ? `✅ ${selected.name} ${t("completed")}` : `❌ ${runResult.error}`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  $effect(() => {
    loadPlugins();
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="panel">
  <h3>{t("title")}</h3>
  <p class="hint">{t("hint")}</p>
  {#if !busy && !plugins.length}
    <div class="empty">{t("noPlugin")}</div>
  {/if}
  <div class="plugin-list">
    {#each plugins as p}
      <button class="plugin-card" class:selected={selected?.id === p.id} onclick={() => { selected = p; runResult = null; }}>
        <span class="name">{p.name}</span>
        <span class="ver">v{p.version}</span>
        <span class="desc">{p.description}</span>
      </button>
    {/each}
  </div>
  {#if selected}
    <div class="run-panel">
      <h4>{t("run")} {selected.name}</h4>
      <div class="row">
        <input type="text" bind:value={filePath} placeholder={t("target")} disabled={busy} />
        <button onclick={runPlugin} disabled={busy} class="btn-primary">{t("runPlugin")}</button>
      </div>
      {#if runResult}
        <pre class="output">{JSON.stringify(runResult.output ?? runResult, null, 2)}</pre>
      {:else}
        <div class="empty compact">{t("pickPlugin")}</div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .plugin-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 8px; margin-bottom: 16px; }
  .empty { padding: 10px 12px; border: 1px dashed var(--divider); border-radius: 8px; color: var(--text-muted); font-size: 11px; margin-bottom: 12px; background: var(--surface-muted); }
  .empty.compact { margin-top: 8px; }
  .plugin-card { text-align: left; border: 1px solid var(--divider); border-radius: 8px; padding: 10px; background: transparent; cursor: pointer; color: inherit; }
  .plugin-card.selected { border-color: var(--primary); background: rgba(99, 102, 241, 0.08); }
  .name { display: block; font-weight: 600; font-size: 12px; }
  .ver { font-size: 10px; color: var(--text-muted); }
  .desc { display: block; font-size: 10px; color: var(--text-secondary); margin-top: 4px; }
  .row { display: flex; gap: 8px; margin-bottom: 8px; }
  input { flex: 1; font-size: 12px; }
  .output { font-size: 10px; font-family: var(--mono); color: var(--text-code); background: var(--surface-code); padding: 10px; border-radius: 6px; overflow: auto; max-height: 40vh; border: 1px solid var(--divider); }
</style>
