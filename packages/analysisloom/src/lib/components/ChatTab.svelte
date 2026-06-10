<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let rootPath = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Chat Artifacts",
      hint: "WhatsApp · Telegram · Signal — SQLite message databases",
      scan: "Scan Chat DBs",
      folder: "Evidence folder with msgstore.db / cache4.db",
      messages: "messages",
      databases: "chat databases",
    },
    id: {
      title: "Artefak Chat",
      hint: "WhatsApp · Telegram · Signal — basis data pesan SQLite",
      scan: "Pindai DB Chat",
      folder: "Folder bukti dengan msgstore.db / cache4.db",
      messages: "pesan",
      databases: "database chat",
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  async function scan() {
    const root = rootPath || (await open({ directory: true }));
    if (!root) return;
    rootPath = typeof root === "string" ? root : rootPath;
    busy = true;
    try {
      results = await timeoutPromise(invoke("scan_chat_artifacts", { root: rootPath }), 120000);
      const total = results.reduce((a, r) => a + r.messageCount, 0);
      msg = `✅ ${results.length} chat databases, ${total} messages`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Chat",
          filePath: rootPath,
          eventType: `chat_${total}`,
        }).catch(() => {});
      }
    } catch (e) {
      results = [];
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (!rootPath) {
      results = [];
    }
  });

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="panel">
  <h3>{t("title")}</h3>
  <p class="hint">{t("hint")}</p>
  <div class="row">
    <input type="text" bind:value={rootPath} placeholder={t("folder")} disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">{t("scan")}</button>
  </div>
  {#each results as res}
    <div class="chat-block">
      <h4>{res.platform} — {res.messageCount} {t("messages")}</h4>
      <p class="db">{res.dbPath}</p>
      {#each res.messages.slice(0, 50) as m}
        <div class="msg">
          <span class="sender">{m.sender}</span>
          <span class="text">{m.message}</span>
          <span class="ts">{m.timestamp}</span>
        </div>
      {/each}
    </div>
  {/each}
</div>

<style>
  .panel { height: 100%; overflow: auto; }
  h3 { margin: 0 0 4px; font-size: 15px; }
  .hint { margin: 0 0 12px; font-size: 11px; color: var(--text-muted); }
  .row { display: flex; gap: 8px; margin-bottom: 12px; }
  input { flex: 1; font-size: 12px; }
  .chat-block { margin-bottom: 16px; border: 1px solid var(--divider); border-radius: 8px; padding: 10px; }
  .db { font-size: 10px; color: var(--text-muted); font-family: var(--mono); margin: 0 0 8px; }
  .msg { display: grid; grid-template-columns: 100px 1fr auto; gap: 8px; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--divider); }
  .sender { font-weight: 600; color: var(--primary); }
  .text { overflow: hidden; text-overflow: ellipsis; }
  .ts { color: var(--text-muted); white-space: nowrap; font-size: 10px; }
</style>
