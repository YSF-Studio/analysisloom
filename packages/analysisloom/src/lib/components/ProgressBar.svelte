<script>
  let { percent = 0, label = "", indeterminate = false } = $props();
</script>

<div class="progress-wrap">
  <div
    class="progress-bar"
    class:indeterminate
    role="progressbar"
    aria-valuenow={indeterminate ? undefined : percent}
    aria-valuemin="0"
    aria-valuemax="100"
    aria-label={label || "Progress"}
  >
    {#if !indeterminate}
      <div class="fill" style="width: {Math.min(100, Math.max(0, percent))}%"></div>
    {:else}
      <div class="fill indeterminate-fill"></div>
    {/if}
  </div>
  {#if label}<span class="progress-label">{label}</span>{/if}
</div>

<style>
  .progress-wrap { margin: 8px 0 12px; }
  .progress-bar {
    height: 6px; background: var(--surface-progress);
    border-radius: 4px; overflow: hidden; position: relative;
  }
  .fill {
    height: 100%; background: var(--primary); border-radius: 4px;
    transition: width 0.3s ease;
  }
  .indeterminate-fill {
    width: 40% !important;
    animation: indeterminate 1.2s ease-in-out infinite;
  }
  @keyframes indeterminate {
    0% { transform: translateX(-100%); }
    100% { transform: translateX(350%); }
  }
  .progress-label { display: block; margin-top: 4px; font-size: 11px; color: var(--text-secondary); }
</style>
