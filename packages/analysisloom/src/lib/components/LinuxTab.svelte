<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let result = $state(null);
  let rootPath = $state("");
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Linux Artifacts",
      hint: "auth.log · audit.log · .bash_history — endpoint activity traces",
      scan: "Scan Linux Logs",
      files: "Files",
      auth: "Auth",
      audit: "Audit",
      history: "History",
      syslog: "Syslog",
      cron: "Cron",
      type: "Type",
      time: "Time",
      user: "User",
      cmd: "Command / Details",
      root: "Linux log folder / evidence folder",
    },
    id: {
      title: "Artefak Linux",
      hint: "auth.log · audit.log · .bash_history — jejak aktivitas endpoint",
      scan: "Pindai Log Linux",
      files: "File",
      auth: "Auth",
      audit: "Audit",
      history: "Riwayat",
      syslog: "Syslog",
      cron: "Cron",
      type: "Tipe",
      time: "Waktu",
      user: "Pengguna",
      cmd: "Perintah / Detail",
      root: "Folder log Linux / folder bukti",
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
      result = null;
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (!rootPath) {
      result = null;
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
    <input type="text" bind:value={rootPath} placeholder={t("root")} disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">{t("scan")}</button>
  </div>
  {#if result}
    <div class="stats">
      <span>{t("files")}: {result.filesParsed}</span>
      <span>{t("auth")}: {result.authEvents}</span>
      <span>{t("audit")}: {result.auditEvents}</span>
      <span>{t("history")}: {result.historyCommands}</span>
      <span>{t("syslog")}: {result.syslogEvents}</span>
      <span>{t("cron")}: {result.cronEvents}</span>
    </div>
    <div class="events">
      <div class="thead"><span>{t("type")}</span><span>{t("time")}</span><span>{t("user")}</span><span>{t("cmd")}</span></div>
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
  .thead { font-weight: 600; color: var(--text-secondary); position: sticky; top: 0; background: var(--surface-header); }
  .type { font-weight: 600; font-size: 10px; text-transform: uppercase; }
  .type-auth_failure { background: rgba(239, 68, 68, 0.05); }
  .cmd { font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); }
</style>
