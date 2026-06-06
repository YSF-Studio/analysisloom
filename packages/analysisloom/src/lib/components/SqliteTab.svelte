<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open } from "@tauri-apps/plugin-dialog";
  import SegmentedControl from "./SegmentedControl.svelte";

  let {
    activeCase,
    busy = $bindable(),
    msg = $bindable(),
    dbPath = $bindable(""),
    timeoutPromise,
  } = $props();

  let viewerMode = $state("preview");
  let dbInfo = $state(null);
  let tables = $state([]);
  let selectedTable = $state("");
  let columns = $state([]);
  let rows = $state([]);
  let customQuery = $state("");
  let lastSql = $state("");

  const modes = [
    { id: "preview", label: "Preview" },
    { id: "hex", label: "Hex" },
    { id: "strings", label: "Strings" },
    { id: "metadata", label: "Metadata" },
  ];

  async function pickDatabase() {
    const picked = await open({
      multiple: false,
      filters: [{ name: "SQLite", extensions: ["db", "sqlite", "sqlite3"] }],
    });
    if (picked) {
      dbPath = picked;
      await loadDatabase();
    }
  }

  async function loadDatabase() {
    if (!dbPath) return;
    busy = true;
    try {
      dbInfo = await timeoutPromise(invoke("sqlite_db_info", { path: dbPath }), 15000);
      tables = dbInfo.tables || [];
      selectedTable = tables[0] || "";
      if (selectedTable) await loadTable(selectedTable);
      else { rows = []; columns = []; }
      msg = `✅ Opened ${tables.length} tables`;
      if (activeCase?.id) {
        invoke("log_action", {
          caseId: activeCase.id,
          action: "SQLITE_OPEN",
          detail: dbPath,
        }).catch(() => {});
      }
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
      dbInfo = null;
      tables = [];
      rows = [];
    }
    busy = false;
  }

  async function loadTable(table) {
    if (!dbPath || !table) return;
    busy = true;
    try {
      const cols = await invoke("sqlite_table_columns", { path: dbPath, table });
      columns = cols.map((c) => c.name);
      const result = await invoke("sqlite_query_table", { path: dbPath, table, limit: 100 });
      rows = result.rows || [];
      lastSql = result.sql || "";
      customQuery = `SELECT * FROM ${table} LIMIT 100`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  async function runCustomQuery() {
    if (!dbPath || !customQuery.trim()) return;
    busy = true;
    try {
      const result = await invoke("sqlite_run_query", {
        path: dbPath,
        query: customQuery,
        limit: 100,
      });
      columns = result.columns || [];
      rows = result.rows || [];
      lastSql = result.sql || customQuery;
      msg = `✅ ${result.rowCount} rows`;
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    busy = false;
  }

  function cellStr(val) {
    if (val == null) return "NULL";
    if (typeof val === "object") return JSON.stringify(val);
    return String(val);
  }

  $effect(() => {
    if (dbPath && !dbInfo && !busy) loadDatabase();
  });
</script>

<div class="sqlite-manager">
  <div class="sqlite-header">
    <div>
      <h3>SQLite Manager</h3>
      <span class="hint">Forensic table browser — WhatsApp, Chrome, iOS backups</span>
    </div>
    <button class="btn-primary" onclick={pickDatabase} disabled={busy}>Open .db</button>
  </div>

  <div class="path-row">
    <input type="text" bind:value={dbPath} placeholder="/path/to/messages.db" disabled={busy} />
    <button onclick={loadDatabase} disabled={busy || !dbPath} class="btn">Load</button>
  </div>

  {#if !dbPath}
    <div class="empty-state">
      <span class="icon">🗄️</span>
      <p>Open a SQLite artifact or select a .db file from NTFS Browser</p>
    </div>
  {:else if !dbInfo && busy}
    <div class="empty-state"><span class="spinner">⏳</span> Reading database…</div>
  {:else if dbInfo}
    <div class="toolbar">
      <label>
        Table
        <select bind:value={selectedTable} onchange={() => loadTable(selectedTable)} disabled={busy}>
          {#each tables as t}
            <option value={t}>{t}</option>
          {/each}
        </select>
      </label>
      <span class="meta dim">{dbInfo.pageCount} pages · {dbInfo.encoding}</span>
    </div>

    <div class="table-wrap">
      {#if columns.length}
        <div class="sql-thead" style="grid-template-columns: repeat({columns.length}, minmax(80px, 1fr))">
          {#each columns as col}
            <span>{col}</span>
          {/each}
        </div>
        {#each rows as row}
          <div class="sql-row" style="grid-template-columns: repeat({columns.length}, minmax(80px, 1fr))">
            {#each row as cell}
              <span class="mono cell" title={cellStr(cell)}>{cellStr(cell)}</span>
            {/each}
          </div>
        {/each}
        {#if !rows.length}
          <div class="empty-row">No rows in this table</div>
        {/if}
      {:else}
        <div class="empty-row">Select a table</div>
      {/if}
    </div>

    <div class="query-row">
      <input type="text" bind:value={customQuery} placeholder="SELECT * FROM messages LIMIT 100" disabled={busy} />
      <button onclick={runCustomQuery} disabled={busy || !customQuery.trim()} class="btn-primary">Run</button>
    </div>

    <div class="viewer-panel">
      <SegmentedControl options={modes} bind:value={viewerMode} />
      <div class="viewer-content">
        {#if viewerMode === "preview"}
          <pre class="preview-text">{lastSql || "—"}</pre>
        {:else if viewerMode === "hex"}
          <pre class="mono dim">SQLite format 3 — read-only forensic browser</pre>
        {:else if viewerMode === "strings"}
          <pre class="preview-text">{rows.flat().map(cellStr).filter((s) => s.length > 2 && s !== "NULL").slice(0, 40).join("\n")}</pre>
        {:else}
          <dl class="meta-list">
            <dt>Path</dt><dd class="mono">{dbInfo.path}</dd>
            <dt>Tables</dt><dd>{tables.join(", ") || "—"}</dd>
            <dt>Pages</dt><dd>{dbInfo.pageCount} × {dbInfo.pageSize} bytes</dd>
            <dt>Encoding</dt><dd>{dbInfo.encoding}</dd>
            <dt>Schema v</dt><dd>{dbInfo.schemaVersion}</dd>
          </dl>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .sqlite-manager { display: flex; flex-direction: column; height: 100%; gap: 10px; }
  .sqlite-header {
    display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;
  }
  .sqlite-header h3 { margin: 0 0 4px; font-size: 15px; font-weight: 600; }
  .hint { font-size: 11px; color: var(--text-muted); }
  .path-row, .query-row { display: flex; gap: 8px; }
  .path-row input, .query-row input { flex: 1; font-size: 12px; }
  .toolbar {
    display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  }
  .toolbar label { font-size: 11px; color: var(--text-muted); display: flex; gap: 6px; align-items: center; }
  .toolbar select {
    background: rgba(0, 0, 0, 0.25); border: 1px solid var(--divider);
    color: var(--text); border-radius: 6px; padding: 4px 8px; font-size: 12px;
  }
  .meta { font-size: 11px; }
  .table-wrap {
    flex: 1; min-height: 0; overflow: auto;
    border: 1px solid var(--divider); border-radius: 8px;
    background: rgba(0, 0, 0, 0.15);
  }
  .sql-thead, .sql-row {
    display: grid; padding: 8px 12px; gap: 8px; font-size: 12px;
    border-bottom: 1px solid var(--divider);
  }
  .sql-thead {
    position: sticky; top: 0; background: rgba(0, 0, 0, 0.35);
    font-weight: 600; color: var(--text-secondary); font-size: 11px;
  }
  .sql-row:hover { background: var(--primary-bg); }
  .cell { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .empty-row, .empty-state {
    display: flex; align-items: center; justify-content: center;
    padding: 32px; color: var(--text-muted); font-size: 13px; gap: 8px;
  }
  .viewer-panel {
    flex-shrink: 0; border-top: 1px solid var(--divider);
    padding-top: 10px; display: flex; flex-direction: column; gap: 8px;
  }
  .viewer-content {
    min-height: 80px; max-height: 140px; overflow: auto;
    background: rgba(0, 0, 0, 0.2); border: 1px solid var(--divider);
    border-radius: 8px; padding: 10px 12px;
  }
  .preview-text, .mono { font-family: var(--mono); font-size: 11px; margin: 0; }
  .dim { color: var(--text-muted); }
  .meta-list {
    margin: 0; font-size: 12px; display: grid;
    grid-template-columns: auto 1fr; gap: 4px 12px;
  }
  .meta-list dt { color: var(--text-muted); }
  .meta-list dd { margin: 0; color: var(--text); word-break: break-all; }
</style>
