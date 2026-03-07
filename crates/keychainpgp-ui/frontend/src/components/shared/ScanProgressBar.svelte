<script lang="ts">
  /**
   * Segmented progress bar for QR code scanning.
   * Each segment represents one data part:
   * - green = scanned directly
   * - blue = recovered via fountain parity
   * - gray = not yet scanned
   * Splits into balanced rows when there are many segments.
   */
  interface Props {
    total: number;
    scanned: Set<number>;
    recovered: Set<number>;
  }
  let { total, scanned, recovered }: Props = $props();

  const MAX_PER_ROW = 25;
  const perRow = $derived(
    total <= MAX_PER_ROW ? total : Math.ceil(total / Math.ceil(total / MAX_PER_ROW)),
  );
</script>

<div class="grid gap-0.5" style="grid-template-columns: repeat({perRow}, 1fr);">
  {#each Array.from({ length: total }, (_, i) => i + 1) as partNum}
    {@const isScanned = scanned.has(partNum)}
    {@const isRecovered = recovered.has(partNum)}
    <div
      class="h-2 rounded-sm transition-colors duration-200
             {isScanned ? 'bg-emerald-400' : isRecovered ? 'bg-sky-400' : 'bg-white/20'}"
    ></div>
  {/each}
</div>
