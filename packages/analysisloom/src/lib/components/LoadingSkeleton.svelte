<script>
  let { rows = 5, columns = 1 } = $props();
</script>

<div class="skeleton" role="status" aria-label="Loading">
  {#each Array(rows) as _, ri}
    <div class="skeleton-row" style="grid-template-columns: repeat({columns}, 1fr)">
      {#each Array(columns) as _, ci}
        <div class="skeleton-cell" style="animation-delay: {(ri * columns + ci) * 80}ms"></div>
      {/each}
    </div>
  {/each}
</div>

<style>
  .skeleton { display: flex; flex-direction: column; gap: 8px; padding: 8px 0; }
  .skeleton-row { display: grid; gap: 10px; }
  .skeleton-cell {
    height: 14px; border-radius: 4px;
    background: linear-gradient(90deg, rgba(255,255,255,0.04) 25%, rgba(255,255,255,0.09) 50%, rgba(255,255,255,0.04) 75%);
    background-size: 200% 100%;
    animation: shimmer 1.4s ease-in-out infinite;
  }
  @keyframes shimmer {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
  }
</style>
