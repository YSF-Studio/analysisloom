<script>
  import SegmentedControl from "./SegmentedControl.svelte";
  import { applyTheme } from "../theme.js";

  let { theme = $bindable("dark"), compact = false, label = "Theme" } = $props();

  const options = $derived([
    { id: "dark", label: compact ? "☾" : "Dark" },
    { id: "light", label: compact ? "☀" : "Light" },
  ]);

  function onThemeChange(id) {
    theme = id;
    applyTheme(id);
  }
</script>

<div class="theme-toggle" class:compact role="group" aria-label={label}>
  {#if !compact}
    <span class="theme-label">{label}</span>
  {/if}
  <SegmentedControl {options} bind:value={theme} onchange={onThemeChange} />
</div>

<style>
  .theme-toggle {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .theme-toggle.compact {
    gap: 0;
  }
  .theme-label {
    font-size: 11px;
    font-weight: 600;
    color: var(--text-muted);
    white-space: nowrap;
  }
  .compact :global(.segment) {
    min-width: 32px;
    padding: 4px 10px;
    font-size: 13px;
  }
</style>
