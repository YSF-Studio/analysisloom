<script>
  let { title, hint = "" } = $props();
</script>

<header class="section-header">
  <h3>{title}</h3>
  {#if hint}<p class="hint">{hint}</p>{/if}
</header>

<style>
  .section-header { margin-bottom: 12px; }
  .section-header h3 {
    margin: 0 0 4px; font-size: 15px; font-weight: 600; color: var(--text);
  }
  .hint { margin: 0; font-size: 11px; color: var(--text-muted); line-height: 1.4; }
</style>
