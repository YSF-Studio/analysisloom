<script>
  import { invoke } from "@tauri-apps/api/core";
  import SectionHeader from "./SectionHeader.svelte";
  import LoadingSkeleton from "./LoadingSkeleton.svelte";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase = $bindable(), busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let cases = $state([]);
  let newCaseName = $state("");
  let operatorName = $state("");
  let loading = $state(false);
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Case Management",
      hint: "Create, open, or delete forensic cases. Shortcut: ⌘N / Ctrl+N",
      caseName: "Case name...",
      operator: "Operator name",
      newCase: "+ New Case",
      deleteCase: "Delete case",
      sealed: "sealed",
      noCases: "No cases yet. Create one to begin forensic analysis.",
      deleteConfirmTitle: "Delete case",
      deleteConfirmBody: "All evidence, findings, and audit data will be permanently removed.",
      cannotDeleteSealed: "🔒 Cannot delete a sealed case",
    },
    id: {
      title: "Manajemen Kasus",
      hint: "Buat, buka, atau hapus kasus forensik. Pintasan: ⌘N / Ctrl+N",
      caseName: "Nama kasus...",
      operator: "Nama operator",
      newCase: "+ Kasus Baru",
      deleteCase: "Hapus kasus",
      sealed: "disegel",
      noCases: "Belum ada kasus. Buat satu untuk memulai analisis forensik.",
      deleteConfirmTitle: "Hapus kasus",
      deleteConfirmBody: "Semua bukti, temuan, dan data audit akan dihapus permanen.",
      cannotDeleteSealed: "🔒 Tidak dapat menghapus kasus yang sudah disegel",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function loadCases() {
    loading = true;
    busy = true;
    try {
      cases = await timeoutPromise(invoke("list_cases"), 5000);
    } catch {
      /* ignore */
    } finally {
      loading = false;
      busy = false;
    }
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

  async function deleteCase(c) {
    if (c.status === "sealed") {
      msg = t("cannotDeleteSealed");
      return;
    }
    if (!confirm(`${t("deleteConfirmTitle")} "${c.name}" (${c.id})?\n\n${t("deleteConfirmBody")}`)) {
      return;
    }
    busy = true;
    try {
      await invoke("delete_case", { id: c.id });
      cases = cases.filter((x) => x.id !== c.id);
      if (activeCase?.id === c.id) activeCase = cases[0] || null;
      msg = `✅ Case deleted: ${c.id}`;
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

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="case-panel">
  <SectionHeader title={t("title")} hint={t("hint")} />
  <div class="new-case">
    <input type="text" bind:value={newCaseName} placeholder={t("caseName")} disabled={busy} aria-label={t("caseName")} />
    <input type="text" bind:value={operatorName} placeholder={t("operator")} disabled={busy} aria-label={t("operator")} />
    <button onclick={createCase} disabled={busy || !newCaseName} class="btn-primary">{t("newCase")}</button>
  </div>

  {#if loading}
    <LoadingSkeleton rows={4} columns={1} />
  {:else}
    <div class="case-list">
      {#each cases as c}
        <div class="case-card" class:active={activeCase?.id === c.id}>
          <button class="case-main" onclick={() => selectCase(c)}>
            <strong>{c.name}</strong>
            <span class="meta">{c.id} | {c.createdAt || c.created_at}</span>
            <span class="status" class:sealed={c.status === "sealed"}>{c.status === "sealed" ? t("sealed") : c.status}</span>
          </button>
          {#if c.status !== "sealed"}
            <button class="btn-delete" title={t("deleteCase")} onclick={() => deleteCase(c)} disabled={busy}>🗑</button>
          {/if}
        </div>
      {/each}
    </div>
  {/if}

  {#if !cases.length && !loading && !busy}
    <p class="empty">{t("noCases")}</p>
  {/if}
</div>

<style>
  .case-panel { height: 100%; }
  .new-case { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .new-case input { flex: 1; min-width: 140px; font-size: 12px; }
  .case-list { display: flex; flex-direction: column; gap: 6px; }
  .case-card {
    display: flex; align-items: stretch; gap: 4px;
    border: 1px solid var(--divider); border-radius: 8px; overflow: hidden;
  }
  .case-card.active { border-color: var(--primary); background: var(--primary-bg); }
  .case-main {
    flex: 1; padding: 12px; border: none; background: transparent;
    color: var(--text); text-align: left; cursor: pointer;
    display: flex; align-items: center; gap: 12px; font: inherit;
  }
  .case-main:hover { background: var(--card-hover); }
  .meta { font-size: 11px; color: var(--text-muted); font-family: var(--mono); }
  .status {
    margin-left: auto; font-size: 10px; padding: 2px 8px; border-radius: 10px;
    background: var(--success-bg); color: var(--success); text-transform: uppercase;
  }
  .status.sealed { background: rgba(245, 158, 11, 0.15); color: var(--warn); }
  .btn-delete {
    padding: 0 12px; border: none; border-left: 1px solid var(--divider);
    background: transparent; color: var(--text-muted); cursor: pointer; font-size: 14px;
  }
  .btn-delete:hover:not(:disabled) { background: var(--danger-bg); color: var(--danger); }
  .empty { color: var(--text-muted); font-size: 12px; }
</style>
