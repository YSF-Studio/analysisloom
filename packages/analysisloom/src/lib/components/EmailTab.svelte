<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";

  let { activeCase, busy = $bindable(), msg = $bindable(), timeoutPromise } = $props();
  let results = $state([]);
  let dirPath = $state("");

  async function scan() {
    const dir = dirPath || (await open({ directory: true }));
    if (!dir) return;
    dirPath = typeof dir === "string" ? dir : dirPath;
    busy = true;
    try {
      results = await timeoutPromise(invoke("scan_email_directory", { dir: dirPath }), 120000);
      const total = results.reduce((a, r) => a + r.messageCount, 0);
      msg = `✅ ${results.length} mailboxes, ${total} messages`;
      if (activeCase?.id) {
        invoke("record_timeline_event", {
          caseId: activeCase.id,
          timestamp: new Date().toISOString(),
          source: "Email",
          filePath: dirPath,
          eventType: `email_${total}`,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }
</script>

<div class="panel">
  <h3>Email Forensics</h3>
  <p class="hint">PST / OST mailbox parsing — headers, folders, message stubs</p>
  <div class="row">
    <input type="text" bind:value={dirPath} placeholder="Folder containing .pst / .ost files" disabled={busy} />
    <button onclick={scan} disabled={busy} class="btn-primary">Scan Mailboxes</button>
  </div>
  {#each results as mb}
    <div class="mailbox">
      <h4>{mb.mailboxType} — {mb.messageCount} messages</h4>
      <p class="path">{mb.filePath}</p>
      <p class="meta">{mb.details} · encrypted={mb.encrypted}</p>
      {#if mb.folders?.length}
        <div class="folders">Folders: {mb.folders.join(", ")}</div>
      {/if}
      {#each mb.messages.slice(0, 30) as m}
        <div class="msg">
          <span class="subj">{m.subject || "(no subject)"}</span>
          <span class="from">{m.sender}</span>
          <span class="date">{m.sentTime}</span>
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
  .mailbox { margin-bottom: 16px; border: 1px solid var(--divider); border-radius: 8px; padding: 10px; }
  .path { font-size: 10px; color: var(--text-muted); font-family: var(--mono); margin: 0 0 4px; }
  .meta, .folders { font-size: 10px; color: var(--text-secondary); margin-bottom: 8px; }
  .msg { display: grid; grid-template-columns: 2fr 1fr auto; gap: 8px; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--divider); }
  .subj { font-weight: 600; overflow: hidden; text-overflow: ellipsis; }
  .from { color: var(--primary); }
  .date { color: var(--text-muted); white-space: nowrap; }
</style>
