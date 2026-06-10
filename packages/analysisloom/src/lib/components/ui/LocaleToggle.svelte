<script>
  import SegmentedControl from "../SegmentedControl.svelte";
  import { getLocale, setLocale } from "../../stores/locale.js";

  let { locale = $bindable(getLocale()), compact = false, label = "Language" } = $props();

  const options = $derived([
    { id: "en", label: compact ? "EN" : "English" },
    { id: "id", label: compact ? "ID" : "Bahasa" },
    { id: "system", label: compact ? "Auto" : "System" },
  ]);

  function onLocaleChange(id) {
    setLocale(id);
  }
</script>

<div class="locale-toggle" class:compact role="group" aria-label={label}>
  {#if !compact}
    <span class="locale-label">{label}</span>
  {/if}
  <SegmentedControl {options} bind:value={locale} onchange={onLocaleChange} />
</div>

<style>
  .locale-toggle {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .locale-toggle.compact {
    gap: 0;
  }
  .locale-label {
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
