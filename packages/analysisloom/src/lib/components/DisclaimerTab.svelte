<script>
import { invoke } from "@tauri-apps/api/core";
import ThemeToggle from "./ThemeToggle.svelte";
import { getResolvedLocale, subscribeLocale } from "../stores/locale.js";

let { theme = $bindable("dark") } = $props();
let info = $state({ features: [] });
let loaded = $state(false);
let locale = $state(getResolvedLocale());

const text = {
  en: {
    subtitle: "Forensic Analysis Workstation",
    features: "Features",
    appearance: "Appearance",
    appearanceBody: "Choose light or dark interface. Your preference is saved automatically.",
    privacy: "Privacy & Security",
    offline: "Fully Offline",
    disclaimer: "Disclaimer",
    developer: "Developer",
    rights: "All rights reserved.",
  },
  id: {
    subtitle: "Stasiun Kerja Analisis Forensik",
    features: "Fitur",
    appearance: "Tampilan",
    appearanceBody: "Pilih antarmuka terang atau gelap. Preferensi Anda disimpan otomatis.",
    privacy: "Privasi & Keamanan",
    offline: "Sepenuhnya Offline",
    disclaimer: "Pernyataan",
    developer: "Pengembang",
    rights: "Seluruh hak dilindungi.",
  },
};

function t(key) {
  return text[locale]?.[key] || text.en[key] || key;
}

async function load() {
    if (loaded) return;
    try {
        info = await invoke("about_info");
        loaded = true;
    } catch(e) { /* fallback */ }
}
$effect(() => { load(); });
$effect(() => subscribeLocale((_, resolved) => {
  locale = resolved;
}));
</script>

<div class="about">
    <header class="hero">
        <img src="/icon.png" class="logo-hero" alt="AnalysisLoom" />
        <h1>{info.appName || "AnalysisLoom"}</h1>
        <span class="version">v{info.version || "0.1.0"}</span>
    </header>

    <p class="subtitle">{t("subtitle")}</p>

    <section class="card">
        <h3>🚀 {t("features")}</h3>
        <ul>
            {#each info.features as f}
                <li>{f}</li>
            {/each}
        </ul>
    </section>

    <section class="card appearance-card">
        <h3>🎨 {t("appearance")}</h3>
        <p>{t("appearanceBody")}</p>
        <ThemeToggle bind:theme label={locale === "id" ? "Tema antarmuka" : "Interface theme"} />
    </section>

    <section class="card offline-card">
        <h3>🔒 {t("privacy")}</h3>
        <p>{info.privacy || (locale === "id" ? "100% offline — tanpa pengumpulan data. Tanpa telemetry, tanpa analytics, tanpa panggilan jaringan eksternal." : "100% offline — zero data collection. No telemetry, no analytics, no external network calls.")}</p>
        <div class="badge">✅ {t("offline")}</div>
    </section>

    <section class="card disclaimer-card">
        <h3>⚖️ {t("disclaimer")}</h3>
        <p class="disclaimer">{info.disclaimer || (locale === "id" ? "Perangkat lunak ini disediakan 'SEBAGAIMANA ADANYA'. Hasil harus diverifikasi secara independen sebelum dipakai dalam proses hukum." : "This software is provided 'AS-IS'. Results should be independently verified before use in legal proceedings.")}</p>
    </section>

    <section class="card">
        <h3>👨‍💻 {t("developer")}</h3>
        <p class="dev">{info.developer || "YSF Studio — Built with ❤️ by Yusuf Shalahuddin"}</p>
        <p class="build">{info.build || (locale === "id" ? "Master Build — Semua fitur dibuka" : "Master Build — All Features Unlocked")}</p>
    </section>

    <footer class="footer">
        <p>YSF Studio © {new Date().getFullYear()} — {t("rights")}</p>
    </footer>
</div>

<style>
.about { max-width: 640px; margin: 0 auto; padding: 20px; }
.hero { text-align: center; margin-bottom: 24px; }
.logo-hero { width: 72px; height: 72px; border-radius: 16px; margin-bottom: 8px; }
.hero h1 { margin: 0; font-size: 28px; color: var(--text); display: inline; }
.version { font-size: 14px; color: var(--text-secondary); margin-left: 8px; }
.subtitle { text-align: center; color: var(--text-secondary); font-size: 13px; margin-bottom: 28px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; }
.card h3 { margin: 0 0 10px; font-size: 15px; color: var(--text); }
.card ul { margin: 0; padding-left: 20px; }
.card li { font-size: 13px; margin-bottom: 6px; color: var(--text-secondary); line-height: 1.4; }
.card p { margin: 0; font-size: 13px; color: var(--text-secondary); line-height: 1.5; }
.appearance-card { border-left: 3px solid var(--primary); }
.appearance-card p { margin-bottom: 12px !important; }
.offline-card { border-left: 3px solid var(--success); }
.disclaimer-card { border-left: 3px solid var(--warn); }
.disclaimer-card .disclaimer { font-style: italic; color: var(--text) !important; }
.badge { display: inline-block; margin-top: 10px; padding: 4px 12px; background: rgba(34,197,94,0.15); color: var(--success); border-radius: 20px; font-size: 12px; font-weight: 600; }
.dev { font-weight: 600; color: var(--text) !important; margin-bottom: 4px !important; }
.build { font-size: 12px !important; color: var(--primary) !important; }
.footer { text-align: center; padding-top: 8px; }
.footer p { font-size: 11px; color: var(--text-secondary); }
</style>
