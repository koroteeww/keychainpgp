<script lang="ts">
  import ModalContainer from "./ModalContainer.svelte";
  import { appStore } from "$lib/stores/app.svelte";
  import { keyStore } from "$lib/stores/keys.svelte";
  import { importKeyBundle } from "$lib/tauri";
  import {
    parseKcpgpPart,
    parseFountainPart,
    fountainRecover,
    cancelScan,
    type FountainPart,
  } from "$lib/qr-scan";
  import { isMobile } from "$lib/platform";
  import { Upload, Camera } from "lucide-svelte";
  import QrScanOverlay from "../shared/QrScanOverlay.svelte";
  import ScanProgressBar from "../shared/ScanProgressBar.svelte";
  import * as m from "$lib/paraglide/messages.js";

  const mobile = isMobile();

  let encryptedData = $state("");
  let passphrase = $state("");
  let error: string | null = $state(null);
  let importing = $state(false);
  let importedCount: number | null = $state(null);

  // Multi-part QR scanning state
  let scanning = $state(false);
  let scannedParts = $state<Map<number, string>>(new Map());
  let scannedFountain = $state<FountainPart[]>([]);
  let totalParts = $state(0);
  let passphraseFromQr = $state(false);

  // Track which parts were scanned directly vs recovered via fountain
  let directScanned = $state<Set<number>>(new Set());
  let fountainRecovered = $state<Set<number>>(new Set());

  async function handleFileLoad(e: Event) {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    encryptedData = await file.text();
  }

  function reassembleAndFinish(): boolean {
    const sorted = Array.from(scannedParts.entries())
      .sort(([a], [b]) => a - b)
      .map(([, data]) => data);
    encryptedData = sorted.join("");
    return true;
  }

  function tryFountainAndCheck(): boolean {
    if (scannedFountain.length === 0 || scannedParts.size >= totalParts) return false;
    const beforeSize = scannedParts.size;
    const recovered = fountainRecover(scannedParts, scannedFountain, totalParts);
    // Track newly recovered parts
    if (scannedParts.size > beforeSize) {
      for (const key of scannedParts.keys()) {
        if (!directScanned.has(key) && !fountainRecovered.has(key)) {
          fountainRecovered = new Set([...fountainRecovered, key]);
        }
      }
      scannedParts = new Map(scannedParts);
    }
    if (recovered) return reassembleAndFinish();
    return false;
  }

  function handleScanResult(content: string): boolean {
    // Auto-detect passphrase QR
    if (content.startsWith("KCPGP-PASS:")) {
      passphrase = content.slice(11);
      passphraseFromQr = true;
      return false; // keep scanning for data parts
    }

    // Try as fountain parity part
    const fountain = parseFountainPart(content);
    if (fountain) {
      totalParts = fountain.total;
      scannedFountain = [...scannedFountain, fountain];
      if (tryFountainAndCheck()) return true;
      return false; // continue scanning
    }

    // Regular data part
    const part = parseKcpgpPart(content);
    if (!part) {
      error = m.error_not_sync_qr();
      return true; // stop
    }

    totalParts = part.total;
    scannedParts.set(part.part, part.data);
    scannedParts = new Map(scannedParts);
    directScanned = new Set([...directScanned, part.part]);

    if (scannedParts.size >= part.total) {
      return reassembleAndFinish();
    }

    if (tryFountainAndCheck()) return true;
    return false; // continue scanning
  }

  function startScan() {
    error = null;
    scannedParts = new Map();
    scannedFountain = [];
    directScanned = new Set();
    fountainRecovered = new Set();
    totalParts = 0;
    passphraseFromQr = false;
    scanning = true;
  }

  function handleCancelScan() {
    cancelScan();
    scanning = false;
  }

  async function handleImport() {
    if (!encryptedData.trim()) {
      error = m.sync_error_no_data();
      return;
    }
    if (!passphrase.trim()) {
      error = m.sync_error_no_passphrase();
      return;
    }
    error = null;
    importing = true;
    try {
      const count = await importKeyBundle(encryptedData.trim(), passphrase.trim());
      importedCount = count;
      await keyStore.refresh();
    } catch (e) {
      error = String(e);
    } finally {
      importing = false;
    }
  }

  // Auto-import when QR scan captured both data and passphrase
  $effect(() => {
    if (
      passphraseFromQr &&
      encryptedData &&
      passphrase &&
      !importing &&
      importedCount === null &&
      !scanning
    ) {
      handleImport();
    }
  });

  const scanProgress = $derived(
    totalParts > 0
      ? m.sync_qr_progress({ current: scannedParts.size, total: totalParts })
      : undefined,
  );

  const scanSegments = $derived(
    totalParts > 0
      ? { total: totalParts, scanned: directScanned, recovered: fountainRecovered }
      : undefined,
  );
</script>

{#if scanning}
  <QrScanOverlay
    onscan={(content) => {
      const done = handleScanResult(content);
      if (done) scanning = false;
      return done;
    }}
    oncancel={handleCancelScan}
    progress={scanProgress}
    segments={scanSegments}
  />
{/if}

<ModalContainer title={m.sync_import_title()}>
  <div class="space-y-4">
    {#if importedCount !== null}
      <!-- Success -->
      <div class="rounded-lg border border-green-200 bg-green-50 p-4 text-green-800">
        <p class="text-sm font-medium">
          {importedCount === 1
            ? m.sync_success_count_one()
            : m.sync_success_count_other({ count: importedCount })}
        </p>
      </div>
      <div class="flex justify-end">
        <button
          class="rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-medium text-white
                 transition-colors hover:bg-[var(--color-primary-hover)]"
          onclick={() => appStore.closeModal()}
        >
          {m.done()}
        </button>
      </div>
    {:else}
      <!-- Data input -->
      <div class="space-y-2">
        {#if mobile}
          <button
            class="flex w-full items-center justify-center gap-2 rounded-lg bg-[var(--color-primary)] px-4 py-3
                   text-sm font-medium text-white
                   transition-colors hover:bg-[var(--color-primary-hover)]"
            onclick={startScan}
          >
            <Camera size={16} />
            {m.onboarding_scan_qr()}
          </button>
          {#if totalParts > 0}
            <div class="space-y-1 px-2">
              <ScanProgressBar
                total={totalParts}
                scanned={directScanned}
                recovered={fountainRecovered}
              />
              <p
                class="text-center text-xs {scannedParts.size >= totalParts
                  ? 'text-[var(--color-success)]'
                  : 'text-[var(--color-text-secondary)]'}"
              >
                {m.sync_qr_progress({ current: scannedParts.size, total: totalParts })}
              </p>
            </div>
          {/if}
          <p class="text-center text-xs text-[var(--color-text-secondary)]">{m.import_or()}</p>
        {/if}
        <p class="text-sm font-medium">{m.sync_file_load()}</p>
        <div class="flex gap-2">
          <label
            class="flex flex-1 cursor-pointer items-center justify-center gap-2 rounded-lg border-2 border-dashed
                   border-[var(--color-border)] px-4 py-3 text-sm
                   transition-colors hover:border-[var(--color-primary)]"
          >
            <Upload size={16} />
            {encryptedData ? m.sync_file_loaded() : m.sync_file_choose()}
            <input type="file" accept=".enc,.txt" class="hidden" onchange={handleFileLoad} />
          </label>
        </div>
        <p class="text-xs text-[var(--color-text-secondary)]">{m.sync_or_paste()}</p>
        <textarea
          bind:value={encryptedData}
          rows={3}
          class="w-full resize-none rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2
                 font-mono text-sm focus:ring-2 focus:ring-[var(--color-primary)] focus:outline-none"
          placeholder={m.sync_paste_placeholder()}
        ></textarea>
      </div>

      <!-- Passphrase input -->
      <div class="space-y-1">
        <label class="block text-sm font-medium" for="sync-passphrase"
          >{m.sync_passphrase_label()}</label
        >
        <input
          id="sync-passphrase"
          type="text"
          bind:value={passphrase}
          class="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-2 font-mono
                 text-sm tracking-wider focus:ring-2 focus:ring-[var(--color-primary)] focus:outline-none"
          placeholder="1234-5678-9012-3456-7890-1234"
        />
      </div>

      {#if error}
        <p class="text-sm text-red-600">{error}</p>
      {/if}

      <div class="flex justify-end gap-2">
        <button
          class="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium
                 transition-colors hover:bg-[var(--color-bg-secondary)]"
          onclick={() => appStore.closeModal()}
        >
          {m.cancel()}
        </button>
        <button
          class="rounded-lg bg-[var(--color-primary)] px-4 py-2 text-sm font-medium text-white
                 transition-colors hover:bg-[var(--color-primary-hover)] disabled:opacity-50"
          onclick={handleImport}
          disabled={importing}
        >
          {importing ? m.sync_importing() : m.sync_import_btn()}
        </button>
      </div>
    {/if}
  </div>
</ModalContainer>
