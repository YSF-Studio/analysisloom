<script>
  import { invoke } from "@tauri-apps/api/core";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

  let {
    activeCase = $bindable(),
    busy = $bindable(),
    msg = $bindable(),
    timeoutPromise,
  } = $props();

  const isSealed = $derived(activeCase?.status === "sealed");
  let sealing = $state(false);
  let locale = $state(getResolvedLocale());

  const text = {
    en: {
      title: "Forensic Report",
      subtitle: "Generate HTML/PDF reports or export a full evidence bundle (ZIP with manifest hashes, evidence files, and reports).",
      openCase: "Open a case first from the Case Manager",
      configuration: "Report Configuration",
      case: "Case:",
      format: "Format:",
      html: "🌐 HTML Report",
      pdf: "📕 PDF Report",
      generate: "📄 Generate Report",
      bundling: "📦 Export Evidence Bundle (ZIP)",
      importManifest: "🔗 Import hash_manifest.json",
      noManifest: "No acquisition manifest — integrity verify on load disabled",
      seal: "🔒 Seal Case (Complete & Immutable)",
      savedBundle: "Bundle saved:",
      reportSaved: "Report saved:",
      auditTitle: "📋 Audit Trail (Last 50 Actions)",
      noAudit: "No audit log entries yet. Actions will be recorded automatically.",
      previewTitle: "📊 Report Contents Preview",
      previewSubtitle: "The report includes all sections below from your active case:",
      generating: "Generating...",
      packaging: "Packaging...",
      importing: "Importing...",
      sealing: "Sealing…",
      reportGenerated: "report generated",
      manifestImported: "Manifest imported",
      sealConfirmTitle: "Seal case",
      sealConfirmBody: "This will mark the case as completed and immutable.",
      sections: [
        ["Case Information", "Name, operator, status, creation date"],
        ["Timeline Events", "Chronological event log (last 100)"],
        ["Evidence Items", "All acquired items with hashes"],
        ["Findings", "Tagged findings with severity"],
        ["Hash Validation", "Acquisition → analysis SHA-256 comparison"],
        ["Tool Notes", "Per-module limitations and scope notes"],
        ["Analyst Notes", "Running examination log"],
        ["Finding Visuals", "Embedded screenshots and text excerpts for bookmarks"],
        ["Audit Trail", "Chained action log with timestamps"],
        ["Evidence Bundle (ZIP)", "Selected evidence files + SHA-256 manifest + HTML/PDF report"],
      ],
    },
    id: {
      title: "Laporan Forensik",
      subtitle: "Buat laporan HTML/PDF atau ekspor bundle bukti lengkap (ZIP dengan hash manifest, file bukti, dan laporan).",
      openCase: "Buka kasus dulu dari Manajer Kasus",
      configuration: "Konfigurasi Laporan",
      case: "Kasus:",
      format: "Format:",
      html: "🌐 Laporan HTML",
      pdf: "📕 Laporan PDF",
      generate: "📄 Buat Laporan",
      bundling: "📦 Ekspor Bundle Bukti (ZIP)",
      importManifest: "🔗 Impor hash_manifest.json",
      noManifest: "Tidak ada manifest akuisisi — verifikasi integritas saat muat dinonaktifkan",
      seal: "🔒 Segel Kasus (Selesai & Tak Dapat Diubah)",
      savedBundle: "Bundle tersimpan:",
      reportSaved: "Laporan tersimpan:",
      auditTitle: "📋 Jejak Audit (50 Aksi Terakhir)",
      noAudit: "Belum ada entri log audit. Aksi akan dicatat otomatis.",
      previewTitle: "📊 Pratinjau Isi Laporan",
      previewSubtitle: "Laporan mencakup semua bagian di bawah dari kasus aktif:",
      generating: "Membuat...",
      packaging: "Mengemas...",
      importing: "Mengimpor...",
      sealing: "Menutup…",
      reportGenerated: "laporan dibuat",
      manifestImported: "Manifest diimpor",
      sealConfirmTitle: "Segel kasus",
      sealConfirmBody: "Ini akan menandai kasus sebagai selesai dan tidak dapat diubah.",
      sections: [
        ["Informasi Kasus", "Nama, operator, status, tanggal pembuatan"],
        ["Event Timeline", "Log peristiwa kronologis (100 terakhir)"],
        ["Item Bukti", "Semua item yang diakuisisi beserta hash"],
        ["Temuan", "Temuan bertag dengan tingkat keparahan"],
        ["Validasi Hash", "Perbandingan SHA-256 akuisisi → analisis"],
        ["Catatan Alat", "Batasan dan catatan cakupan per modul"],
        ["Catatan Analis", "Log pemeriksaan berjalan"],
        ["Visual Temuan", "Screenshot dan cuplikan teks tersemat untuk bookmark"],
        ["Jejak Audit", "Log aksi berantai dengan timestamp"],
        ["Bundle Bukti (ZIP)", "File bukti terpilih + manifest SHA-256 + laporan HTML/PDF"],
      ],
    },
  };

  function t(key) {
    return text[locale]?.[key] || text.en[key] || key;
  }

  let sections = $derived.by(() => text[locale]?.sections || text.en.sections);

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
        detail: `${format.toUpperCase()} ${t("reportGenerated")}`,
      });
    } catch (e) {
      const err = typeof e === 'string' ? e : String(e);
      msg = `❌ ${err}`;
    } finally {
      generating = false;
      busy = false;
    }
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
      bundlePath = "";
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      bundling = false;
    }
  }

  async function loadAuditLog() {
    if (!activeCase?.id) return;
    try {
      auditLog = await invoke("get_audit_log", { caseId: activeCase.id });
    } catch {
      auditLog = [];
    }
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
      msg = `✅ ${t("manifestImported")} — ${result.fileCount} files from ${result.source}${sig}`;
      await loadAuditLog();
    } catch (e) {
      manifestInfo = null;
      msg = `❌ ${typeof e === "string" ? e : String(e)}`;
    } finally {
      importingManifest = false;
    }
  }

  async function sealCase() {
    if (!activeCase?.id || isSealed) return;
    const operator = activeCase.operator || "Analyst";
    if (!confirm(`${t("sealConfirmTitle")} "${activeCase.name}"?\n\n${t("sealConfirmBody")}\n\nOperator: ${operator}`)) {
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
    } finally {
      sealing = false;
    }
  }

  // Load audit log when case changes
  $effect(() => {
    if (activeCase?.id) {
      loadAuditLog();
      loadManifestInfo();
    } else {
      auditLog = [];
      manifestInfo = null;
      reportPath = "";
      bundlePath = "";
      generating = false;
      bundling = false;
      importingManifest = false;
      sealing = false;
    }
  });

  function severityColor(s) {
    if (s === "critical") return "var(--danger)";
    if (s === "warning") return "var(--warn)";
    return "var(--text-secondary)";
  }

  $effect(() => subscribeLocale((_, resolved) => {
    locale = resolved;
  }));
</script>

<div class="report-container">
  <h3>📄 {t("title")}</h3>
  <p class="subtitle">{t("subtitle")}</p>

  {#if !activeCase?.id}
    <div class="empty-state">
      <span style="font-size:32px">📂</span>
      <p>{t("openCase")}</p>
    </div>
  {:else}
    <!-- Format selection -->
    <div class="card">
      <h4>{t("configuration")}</h4>
      <div class="row">
        <span class="field-label">{t("case")} <strong>{activeCase.name}</strong></span>
      </div>
      <div class="row">
        <span class="field-label">{t("format")}</span>
        <div class="format-pills">
          <button class="pill" class:active={format === 'html'} onclick={() => format = 'html'}>
            {t("html")}
          </button>
          <button class="pill" class:active={format === 'pdf'} onclick={() => format = 'pdf'}>
            {t("pdf")}
          </button>
        </div>
      </div>

      <button class="btn-generate" onclick={generateReport} disabled={generating}>
        {generating ? `🔄 ${t("generating")}` : t("generate")}
      </button>

      <button class="btn-bundle" onclick={exportBundle} disabled={bundling}>
        {bundling ? `🔄 ${t("packaging")}` : t("bundling")}
      </button>

      <div class="manifest-row">
        <button class="btn-manifest" onclick={importManifest} disabled={importingManifest}>
          {importingManifest ? `🔄 ${t("importing")}` : t("importManifest")}
        </button>
        {#if manifestInfo?.loaded}
          <span class="manifest-badge">
            ✓ {manifestInfo.fileCount} files from {manifestInfo.source}
            {#if manifestInfo.signatureVerified} — Ed25519 signed{/if}
          </span>
        {:else}
          <span class="manifest-badge warn">{t("noManifest")}</span>
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
          {sealing ? `🔒 ${t("sealing")}` : t("seal")}
        </button>
      {/if}

      {#if bundlePath}
        <div class="report-link bundle">
          <span class="icon">📦</span>
          <div>
            <strong>{t("savedBundle")}</strong><br />
            <code>{bundlePath}</code>
          </div>
        </div>
      {/if}

      {#if reportPath}
        <div class="report-link">
          <span class="icon">✅</span>
          <div>
            <strong>{t("reportSaved")}</strong><br />
            <code>{reportPath}</code>
          </div>
        </div>
      {/if}
    </div>

    <!-- Audit Trail -->
    <div class="card" style="margin-top:16px">
      <h4>{t("auditTitle")}</h4>
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
        <p class="muted">{t("noAudit")}</p>
      {/if}
    </div>

    <!-- Report Preview -->
    <div class="card" style="margin-top:16px">
      <h4>{t("previewTitle")}</h4>
      <p class="muted">{t("previewSubtitle")}</p>
      <ul class="preview-list">
        {#each sections as [sectionTitle, sectionDetail]}
          <li><strong>{sectionTitle}</strong> — {sectionDetail}</li>
        {/each}
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
    background: var(--primary); border-color: var(--primary); color: var(--text-on-primary); font-weight: 600;
  }

  .btn-generate {
    padding: 10px 24px; background: var(--primary); color: var(--text-on-primary);
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
    padding: 6px 4px; border-bottom: 1px solid var(--divider);
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
