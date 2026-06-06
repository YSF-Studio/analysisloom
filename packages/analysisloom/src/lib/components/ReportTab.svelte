<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";

  let {
    activeCase = $bindable(),
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
  } = $props();

  const isSealed = $derived(activeCase?.status === "sealed");
  let sealing = $state(false);

  let format = $state("html");
  let generating = $state(false);
  let bundling = $state(false);
  let reportPath = $state("");
  let bundlePath = $state("");
  let auditLog = $state([]);
  let manifestInfo = $state(null);
  let importingManifest = $state(false);

  async function generateReport() {
    if (!activeCase?.id) return;
    generating = true;
    reportPath = "";
    try {
      const path = await invoke("generate_case_report", {
        caseId: activeCase.id,
        format,
      });
      reportPath = path;
      // Log the action
      await invoke("log_action", {
        caseId: activeCase.id,
        action: "GENERATE_REPORT",
        detail: format.toUpperCase() + " report generated",
      });
    } catch (e) {
      const err = typeof e === 'string' ? e : String(e);
      msg = `❌ ${err}`;
    }
    generating = false;
    busy = false;
  }

  async function exportBundle() {
    if (!activeCase?.id) return;
    const dest = await save({
      defaultPath: `analysisloom_${activeCase.id.slice(0, 8)}_bundle.zip`,
      filters: [{ name: "ZIP Bundle", extensions: ["zip"] }],
    });
    if (!dest) return;
    bundling = true;
    try {
      const result = await timeoutPromise(
        invoke("export_case_bundle", { caseId: activeCase.id, outputPath: dest }),
        180000
      );
      bundlePath = result.zipPath;
      msg = `✅ Bundle exported — ${result.fileCount} files, manifest ${result.manifestSha256.slice(0, 16)}…`;
      await loadAuditLog();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    bundling = false;
  }

  async function loadAuditLog() {
    if (!activeCase?.id) return;
    try {
      auditLog = await invoke("get_audit_log", { caseId: activeCase.id });
    } catch (e) {}
  }

  async function loadManifestInfo() {
    if (!activeCase?.id) {
      manifestInfo = null;
      return;
    }
    try {
      manifestInfo = await invoke("get_case_manifest", { caseId: activeCase.id });
    } catch {
      manifestInfo = null;
    }
  }

  async function importManifest() {
    if (!activeCase?.id) return;
    const picked = await open({
      multiple: false,
      filters: [{ name: "Hash Manifest", extensions: ["json"] }],
    });
    if (!picked) return;
    importingManifest = true;
    try {
      const result = await invoke("import_hash_manifest", {
        caseId: activeCase.id,
        path: picked,
      });
      manifestInfo = await invoke("get_case_manifest", { caseId: activeCase.id });
      const sig = result.signatureVerified ? " (Ed25519 verified)" : "";
      msg = `✅ Manifest imported — ${result.fileCount} files from ${result.source}${sig}`;
      await loadAuditLog();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    importingManifest = false;
  }

  async function sealCase() {
    if (!activeCase?.id || isSealed) return;
    const operator = activeCase.operator || "Analyst";
    if (!confirm(`Seal case "${activeCase.name}" as completed and immutable?\n\nOperator: ${operator}`)) {
      return;
    }
    sealing = true;
    try {
      const updated = await invoke("seal_case", { caseId: activeCase.id, operator });
      activeCase = updated;
      msg = `🔒 Case sealed — digest ${updated.sealHash?.slice(0, 16) || ""}…`;
      await loadAuditLog();
    } catch (e) {
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    }
    sealing = false;
  }

  // Load audit log when case changes
  $effect(() => {
    if (activeCase?.id) {
      loadAuditLog();
      loadManifestInfo();
    }
  });

  function severityColor(s) {
    if (s === "critical") return "var(--danger)";
    if (s === "warning") return "var(--warn)";
    return "var(--text-secondary)";
  }
</script>

<div class="report-container">
  <h3>📄 Forensic Report</h3>
  <p class="subtitle">
    Generate HTML/PDF reports or export a full evidence bundle (ZIP with manifest hashes, evidence files, and reports).
  </p>

  {#if !activeCase?.id}
    <div class="empty-state">
      <span style="font-size:32px">📂</span>
      <p>Open a case first from the Case Manager</p>
    </div>
  {:else}
    <!-- Format selection -->
    <div class="card">
      <h4>Report Configuration</h4>
      <div class="row">
        <label>Case: <strong>{activeCase.name}</strong></label>
      </div>
      <div class="row">
        <label>Format:</label>
        <div class="format-pills">
          <button class="pill" class:active={format === 'html'} onclick={() => format = 'html'}>
            🌐 HTML Report
          </button>
          <button class="pill" class:active={format === 'pdf'} onclick={() => format = 'pdf'}>
            📕 PDF Report
          </button>
        </div>
      </div>

      <button class="btn-generate" onclick={generateReport} disabled={generating}>
        {generating ? '🔄 Generating...' : '📄 Generate Report'}
      </button>

      <button class="btn-bundle" onclick={exportBundle} disabled={bundling}>
        {bundling ? '🔄 Packaging...' : '📦 Export Evidence Bundle (ZIP)'}
      </button>

      <div class="manifest-row">
        <button class="btn-manifest" onclick={importManifest} disabled={importingManifest}>
          {importingManifest ? '🔄 Importing...' : '🔗 Import hash_manifest.json'}
        </button>
        {#if manifestInfo?.loaded}
          <span class="manifest-badge">
            ✓ {manifestInfo.fileCount} files from {manifestInfo.source}
            {#if manifestInfo.signatureVerified} — Ed25519 signed{/if}
          </span>
        {:else}
          <span class="manifest-badge warn">No acquisition manifest — integrity verify on load disabled</span>
        {/if}
      </div>

      {#if isSealed}
        <div class="sealed-banner">
          🔒 Case sealed {activeCase.sealedAt ? `on ${activeCase.sealedAt}` : ""}
          {#if activeCase.sealHash}
            — digest <code>{activeCase.sealHash.slice(0, 24)}…</code>
          {/if}
        </div>
      {:else}
        <button class="btn-seal" onclick={sealCase} disabled={sealing}>
          {sealing ? "🔒 Sealing…" : "🔒 Seal Case (Complete & Immutable)"}
        </button>
      {/if}

      {#if bundlePath}
        <div class="report-link bundle">
          <span class="icon">📦</span>
          <div>
            <strong>Bundle saved:</strong><br />
            <code>{bundlePath}</code>
          </div>
        </div>
      {/if}

      {#if reportPath}
        <div class="report-link">
          <span class="icon">✅</span>
          <div>
            <strong>Report saved:</strong><br />
            <code>{reportPath}</code>
          </div>
        </div>
      {/if}
    </div>

    <!-- Audit Trail -->
    <div class="card" style="margin-top:16px">
      <h4>📋 Audit Trail (Last 50 Actions)</h4>
      {#if auditLog.length > 0}
        <div class="audit-table">
          {#each auditLog as entry}
            <div class="audit-row">
              <span class="audit-time">{entry.timestamp}</span>
              <span class="audit-action">{entry.action}</span>
              <span class="audit-detail">{entry.detail}</span>
            </div>
          {/each}
        </div>
      {:else}
        <p class="muted">No audit log entries yet. Actions will be recorded automatically.</p>
      {/if}
    </div>

    <!-- Report Preview -->
    <div class="card" style="margin-top:16px">
      <h4>📊 Report Contents Preview</h4>
      <p class="muted">The report includes all sections below from your active case:</p>
      <ul class="preview-list">
        <li><strong>Case Information</strong> — Name, operator, status, creation date</li>
        <li><strong>Timeline Events</strong> — Chronological event log (last 100)</li>
        <li><strong>Evidence Items</strong> — All acquired items with hashes</li>
        <li><strong>Findings</strong> — Tagged findings with severity</li>
        <li><strong>Hash Chain Validation</strong> — Acquisition → analysis SHA-256 comparison (NIST §3.4.1)</li>
        <li><strong>Tool Limitations</strong> — Per-module disclaimers (ISO 27042 §10.1)</li>
        <li><strong>Analyst Notes</strong> — Running examination log (SWGDE §4.4)</li>
        <li><strong>Finding Visuals</strong> — Embedded screenshots and text excerpts for bookmarks</li>
        <li><strong>Audit Trail</strong> — Chained action log with timestamps</li>
        <li><strong>Evidence Bundle (ZIP)</strong> — Selected evidence files + SHA-256 manifest + HTML/PDF report</li>
      </ul>
    </div>
  {/if}
</div>

<style>
  .report-container h3 { margin: 0 0 4px; font-size: 18px; color: var(--text); }
  .subtitle { color: var(--text-secondary); font-size: 13px; margin: 0 0 20px; }

  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: var(--radius-lg); padding: 16px;
  }
  .card h4 { margin: 0 0 12px; font-size: 14px; color: var(--text); }

  .row { margin-bottom: 12px; font-size: 13px; color: var(--text-secondary); }

  .format-pills { display: flex; gap: 8px; margin-top: 4px; }
  .pill {
    padding: 6px 16px; border: 1px solid var(--border); border-radius: 20px;
    background: transparent; color: var(--text-secondary); font-size: 12px;
    cursor: pointer; transition: all 0.15s;
  }
  .pill:hover { border-color: var(--primary); color: var(--text); }
  .pill.active {
    background: var(--primary); border-color: var(--primary); color: #fff; font-weight: 600;
  }

  .btn-generate {
    padding: 10px 24px; background: var(--primary); color: #fff;
    border: none; border-radius: 8px; font-size: 13px; font-weight: 600;
    cursor: pointer; margin-top: 4px; transition: filter 0.15s;
  }
  .btn-generate:hover:not(:disabled) { filter: brightness(1.1); }
  .btn-generate:disabled { opacity: 0.4; cursor: not-allowed; }

  .btn-bundle {
    padding: 10px 24px; background: transparent; color: var(--primary);
    border: 2px solid var(--primary); border-radius: 8px; font-size: 13px; font-weight: 600;
    cursor: pointer; margin-top: 8px; margin-left: 8px; transition: background 0.15s;
  }
  .btn-bundle:hover:not(:disabled) { background: var(--primary-bg); }
  .btn-bundle:disabled { opacity: 0.4; cursor: not-allowed; }
  .btn-manifest {
    padding: 8px 16px; background: transparent; color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: 8px; font-size: 12px;
    font-weight: 600; cursor: pointer; margin-top: 8px;
  }
  .btn-manifest:hover:not(:disabled) { border-color: var(--primary); color: var(--primary); }
  .btn-manifest:disabled { opacity: 0.4; cursor: not-allowed; }
  .manifest-row { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-top: 8px; }
  .manifest-badge { font-size: 11px; color: var(--success); }
  .manifest-badge.warn { color: var(--warn, #f59e0b); }
  .btn-seal {
    margin-top: 10px; padding: 10px 20px; width: 100%;
    background: rgba(245,158,11,0.12); border: 2px solid var(--warn, #f59e0b);
    color: var(--warn, #f59e0b); border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
  }
  .btn-seal:hover:not(:disabled) { background: rgba(245,158,11,0.2); }
  .btn-seal:disabled { opacity: 0.5; cursor: not-allowed; }
  .sealed-banner {
    margin-top: 10px; padding: 10px 14px; border-radius: 8px;
    background: rgba(245,158,11,0.1); border: 1px solid var(--warn, #f59e0b);
    font-size: 12px; color: var(--warn, #f59e0b);
  }
  .sealed-banner code { font-family: var(--mono); font-size: 10px; }
  .report-link.bundle { background: rgba(59,130,246,0.08); border-color: var(--primary); }

  .report-link {
    display: flex; align-items: flex-start; gap: 10px;
    margin-top: 12px; padding: 10px; border-radius: 8px;
    background: rgba(34,197,94,0.08); border: 1px solid var(--success);
    font-size: 13px;
  }
  .report-link .icon { font-size: 18px; flex-shrink: 0; }
  .report-link code {
    font-family: var(--mono); font-size: 11px; color: var(--text-secondary);
    word-break: break-all;
  }

  /* Audit table */
  .audit-table { max-height: 240px; overflow-y: auto; }
  .audit-row {
    display: grid; grid-template-columns: 140px 120px 1fr; gap: 8px;
    padding: 6px 4px; border-bottom: 1px solid rgba(255,255,255,0.03);
    font-size: 11px;
  }
  .audit-time { color: var(--text-muted); font-family: var(--mono); }
  .audit-action { color: var(--primary); font-weight: 600; font-family: var(--mono); }
  .audit-detail { color: var(--text-secondary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .preview-list { margin: 8px 0 0; padding-left: 20px; }
  .preview-list li { font-size: 12px; color: var(--text-secondary); margin-bottom: 4px; }

  .empty-state {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    padding: 60px 20px; text-align: center;
  }
  .empty-state p { color: var(--text-muted); font-size: 14px; margin-top: 12px; }

  .muted { color: var(--text-muted); font-size: 12px; }
</style>
