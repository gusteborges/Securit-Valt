<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import {
    clear as clearSystemClipboard,
    writeSecret,
  } from "@tauri-apps/plugin-clipboard-manager";
  import {
    AUTO_LOCK_MS,
    clearClipboard,
    CLIPBOARD_CLEAR_MS,
    createInactivityTimer,
    filterEntries,
    generatePassword as generateSecurePassword,
    MAX_GENERATED_PASSWORD_LENGTH,
    MIN_GENERATED_PASSWORD_LENGTH,
    usernameForEditing,
    MIN_MASTER_PASSWORD_LENGTH,
    validateEntryFields,
    validateMasterPassword,
    type PasswordGeneratorOptions,
    type VaultEntry,
  } from "$lib/vault";

  interface VaultStatus {
    initialized: boolean;
    unlocked: boolean;
  }

  function submitAuth(event: SubmitEvent) {
    event.preventDefault();
    void (status === "setup" ? initializeVault() : unlockVault());
  }

  let status = $state<"loading" | "setup" | "locked" | "unlocked">("loading");
  let activeTab = $state("cofre");
  let entries = $state<VaultEntry[]>([]);
  let listError = $state("");
  let favoriteBusyId = $state<string | null>(null);

  // Telas de criação e desbloqueio
  let masterPassword = $state("");
  let confirmPassword = $state("");
  let authError = $state("");
  let authBusy = $state(false);

  // Modal "Novo Item"
  let modalOpen = $state(false);
  let newDomain = $state("");
  let newUsername = $state("");
  let newPassword = $state("");
  let modalError = $state("");
  let modalBusy = $state(false);

  // Busca no cofre
  let searchQuery = $state("");
  let generatorLength = $state(20);
  let generatorOptions = $state<PasswordGeneratorOptions>({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });
  let generatedPassword = $state("");
  let generatorError = $state("");

  // Edição e exclusão de entradas
  let editingId = $state<string | null>(null);
  let deletingId = $state<string | null>(null);
  let itemBusy = $state(false);

  // Copiar senha com limpeza automática da área de transferência
  let clipboardTimer: ReturnType<typeof setTimeout> | null = null;
  let clipboardValue = $state("");
  let clipboardNotice = $state("");
  let lastActivityAt = 0;
  let lockInProgress = false;
  const inactivityTimer = createInactivityTimer(() => {
    void lockVault(true);
  }, AUTO_LOCK_MS);

  let filteredEntries = $derived(
    filterEntries(entries, searchQuery, activeTab === "favoritos"),
  );

  function errorMessage(e: unknown): string {
    if (typeof e === "string") return e;
    return e instanceof Error ? e.message : String(e);
  }

  async function checkStatus() {
    try {
      const s = await invoke<VaultStatus>("vault_status");
      if (!s.initialized) {
        status = "setup";
      } else if (s.unlocked) {
        await enterVault();
      } else {
        status = "locked";
      }
    } catch (e) {
      authError = errorMessage(e);
      status = "locked";
    }
  }

  async function enterVault() {
    masterPassword = "";
    confirmPassword = "";
    authError = "";
    status = "unlocked";
    lastActivityAt = Date.now();
    inactivityTimer.reset();
    await loadEntries();
  }

  async function loadEntries() {
    listError = "";
    try {
      entries = await invoke<VaultEntry[]>("list_entries");
    } catch (e) {
      listError = errorMessage(e);
    }
  }

  async function initializeVault() {
    authError = "";
    const validationError = validateMasterPassword(masterPassword, confirmPassword);
    if (validationError) {
      authError = validationError;
      return;
    }

    authBusy = true;
    try {
      await invoke("initialize_vault", { password: masterPassword });
      await enterVault();
    } catch (e) {
      authError = errorMessage(e);
    } finally {
      authBusy = false;
    }
  }

  async function unlockVault() {
    authError = "";
    authBusy = true;
    try {
      await invoke("unlock_vault", { password: masterPassword });
      await enterVault();
    } catch (e) {
      authError = errorMessage(e);
    } finally {
      authBusy = false;
    }
  }

  async function lockVault(automatic = false) {
    if (lockInProgress) return;
    lockInProgress = true;
    try {
      await invoke("lock_vault");
    } catch (e) {
      listError = errorMessage(e);
      lockInProgress = false;
      if (status === "unlocked") recordActivity();
      return;
    }
    inactivityTimer.cancel();
    const clipboardCleared = await limparClipboard();
    entries = [];
    modalOpen = false;
    editingId = null;
    deletingId = null;
    searchQuery = "";
    masterPassword = "";
    confirmPassword = "";
    authError = automatic ? "Cofre bloqueado após cinco minutos sem atividade." : "";
    if (!clipboardCleared) {
      authError = "Cofre bloqueado, mas não foi possível limpar a área de transferência. Verifique as permissões do sistema.";
    }
    status = "locked";
    lockInProgress = false;
  }

  function novoItem() {
    editingId = null;
    newDomain = "";
    newUsername = "";
    newPassword = "";
    modalError = "";
    modalOpen = true;
  }

  async function editarItem(entry: VaultEntry) {
    listError = "";
    let senha: string;
    try {
      senha = await invoke<string>("get_password", { id: entry.id });
    } catch (e) {
      listError = errorMessage(e);
      return;
    }
    editingId = entry.id;
    newDomain = entry.domain;
    newUsername = usernameForEditing(entry.username);
    newPassword = senha;
    modalError = "";
    modalOpen = true;
  }

  function fecharModal() {
    modalOpen = false;
    editingId = null;
    newPassword = "";
  }

  async function copiarSenha(entry: VaultEntry) {
    let senha: string;
    try {
      senha = await invoke<string>("get_password", { id: entry.id });
    } catch (e) {
      clipboardNotice = `Não foi possível copiar a senha: ${errorMessage(e)}`;
      return;
    }
    await copySecret(senha);
  }

  async function copySecret(secret: string) {
    try {
      await writeSecret(secret);
    } catch (e) {
      clipboardNotice = `Não foi possível copiar a senha: ${errorMessage(e)}`;
      return;
    }
    clipboardValue = secret;
    clipboardNotice = "Senha copiada. A área de transferência será limpa após 15 segundos.";
    if (clipboardTimer) clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(limparClipboard, CLIPBOARD_CLEAR_MS);
  }

  async function toggleFavorite(entry: VaultEntry) {
    if (favoriteBusyId) return;
    favoriteBusyId = entry.id;
    listError = "";
    try {
      await invoke("set_favorite", { id: entry.id, favorite: !entry.favorite });
      await loadEntries();
    } catch (e) {
      listError = errorMessage(e);
    } finally {
      favoriteBusyId = null;
    }
  }

  function generateNewPassword() {
    generatorError = "";
    try {
      generatedPassword = generateSecurePassword(generatorLength, generatorOptions);
    } catch (e) {
      generatedPassword = "";
      generatorError = errorMessage(e);
    }
  }

  async function limparClipboard(): Promise<boolean> {
    if (clipboardTimer) clearTimeout(clipboardTimer);
    clipboardTimer = null;
    if (!clipboardValue) return true;
    try {
      await clearClipboard(clearSystemClipboard);
      clipboardValue = "";
      clipboardNotice = "Área de transferência limpa.";
      if (status === "locked" && authError.startsWith("Cofre bloqueado, mas não foi possível limpar")) {
        authError = "Área de transferência limpa.";
      }
      return true;
    } catch (e) {
      clipboardNotice = `Não foi possível limpar a área de transferência: ${errorMessage(e)}`;
      return false;
    }
  }

  function recordActivity() {
    if (status !== "unlocked") return;
    if (lastActivityAt > 0 && Date.now() - lastActivityAt >= AUTO_LOCK_MS) {
      void lockVault(true);
      return;
    }
    lastActivityAt = Date.now();
    inactivityTimer.reset();
  }

  function retryClipboardClear() {
    if (clipboardValue && !clipboardTimer && document.visibilityState === "visible") {
      void limparClipboard();
    }
  }

  function handleVisibilityChange() {
    if (document.visibilityState === "visible") {
      recordActivity();
      retryClipboardClear();
    }
  }

  async function salvarItem() {
    modalError = "";
    const validationError = validateEntryFields(newDomain, newPassword);
    if (validationError) {
      modalError = validationError;
      return;
    }

    modalBusy = true;
    try {
      const dados = {
        domain: newDomain.trim(),
        username: newUsername.trim(),
        password: newPassword,
      };
      if (editingId) {
        await invoke("update_entry", { id: editingId, ...dados });
      } else {
        await invoke("add_entry", dados);
      }
      fecharModal();
      await loadEntries();
    } catch (e) {
      modalError = errorMessage(e);
    } finally {
      modalBusy = false;
    }
  }

  async function excluirItem(id: string) {
    itemBusy = true;
    try {
      await invoke("delete_entry", { id });
      deletingId = null;
      await loadEntries();
    } catch (e) {
      listError = errorMessage(e);
    } finally {
      itemBusy = false;
    }
  }

  onMount(() => {
    const activityEvents: (keyof WindowEventMap)[] = [
      "pointerdown",
      "pointermove",
      "keydown",
      "wheel",
      "touchstart",
    ];
    activityEvents.forEach((event) => window.addEventListener(event, recordActivity));
    window.addEventListener("focus", recordActivity);
    window.addEventListener("focus", retryClipboardClear);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    checkStatus();

    return () => {
      inactivityTimer.cancel();
      activityEvents.forEach((event) => window.removeEventListener(event, recordActivity));
      window.removeEventListener("focus", recordActivity);
      window.removeEventListener("focus", retryClipboardClear);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      if (clipboardTimer) clearTimeout(clipboardTimer);
      void limparClipboard();
    };
  });
</script>

{#if status === "loading"}
<main class="flex h-screen w-screen bg-bg text-gray-400 items-center justify-center font-sans">
  <p class="text-sm">Carregando cofre...</p>
</main>
{:else if status === "setup" || status === "locked"}
<main class="flex h-screen w-screen bg-bg text-gray-100 items-center justify-center font-sans">
  <form
    class="w-full max-w-sm bg-surface p-8 rounded-xl border border-gray-800 space-y-4"
    onsubmit={submitAuth}
  >
    <div class="text-center">
      <h1 class="text-2xl font-bold tracking-tight text-primary">SecureVault 🔒</h1>
      <p class="text-xs text-gray-500 mt-1">
        {status === "setup"
          ? "Crie a senha mestra do seu cofre"
          : "Digite a senha mestra para desbloquear"}
      </p>
    </div>

    <input
      type="password"
      bind:value={masterPassword}
      placeholder="Senha mestra"
      autocomplete="off"
      required
      class="w-full bg-bg border border-gray-700 text-sm rounded-lg py-2 px-3 focus:outline-none focus:border-primary text-gray-200 placeholder-gray-600"
    />

    {#if status === "setup"}
      <input
        type="password"
        bind:value={confirmPassword}
        placeholder="Confirmar senha mestra"
        autocomplete="off"
        required
        class="w-full bg-bg border border-gray-700 text-sm rounded-lg py-2 px-3 focus:outline-none focus:border-primary text-gray-200 placeholder-gray-600"
      />
      <p class="text-xs text-gray-500">
        Mínimo de {MIN_MASTER_PASSWORD_LENGTH} caracteres. Essa senha não pode ser recuperada.
      </p>
    {/if}

    {#if authError}
      <p class="text-sm text-danger">{authError}</p>
    {/if}

    {#if clipboardNotice}
      <p class="text-sm {clipboardNotice.startsWith('Não foi possível') ? 'text-danger' : 'text-primary'}">{clipboardNotice}</p>
    {/if}

    <button
      type="submit"
      disabled={authBusy}
      class="w-full bg-primary hover:bg-primary/90 disabled:opacity-50 text-bg font-bold py-2 rounded-lg text-sm transition-transform active:scale-95"
    >
      {status === "setup" ? "Criar cofre" : "Desbloquear"}
    </button>
  </form>
</main>
{:else}
<main class="flex h-screen w-screen bg-bg text-gray-100 overflow-hidden font-sans">
  
  <aside class="w-64 bg-surface flex flex-col border-r border-gray-800">
    <div class="p-6">
      <h1 class="text-2xl font-bold tracking-tight text-primary">SecureVault 🔒</h1>
      <p class="text-xs text-gray-500 mt-1">Cofre Local Criptografado</p>
    </div>

    <nav class="flex-1 px-4 space-y-2">
      <button 
        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors
        {activeTab === 'cofre' ? 'bg-primary/10 text-primary' : 'text-gray-400 hover:bg-white/5 hover:text-white'}"
        onclick={() => activeTab = 'cofre'}
      >
        <span>🔐</span> Todos os Itens
      </button>

      <button 
        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors
        {activeTab === 'favoritos' ? 'bg-primary/10 text-primary' : 'text-gray-400 hover:bg-white/5 hover:text-white'}"
        onclick={() => activeTab = 'favoritos'}
      >
        <span>⭐</span> Favoritos
      </button>

      <button 
        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors
        {activeTab === 'gerador' ? 'bg-primary/10 text-primary' : 'text-gray-400 hover:bg-white/5 hover:text-white'}"
        onclick={() => activeTab = 'gerador'}
      >
        <span>⚡</span> Gerador
      </button>
    </nav>

    <div class="p-4 border-t border-gray-800">
      <button
        onclick={() => lockVault()}
        class="w-full flex items-center gap-3 px-4 py-2 text-sm text-gray-500 hover:text-danger transition-colors"
      >
        <span>🚪</span> Bloquear Cofre
      </button>
    </div>
  </aside>

  <div class="flex-1 flex flex-col h-full bg-bg">
    
    {#if activeTab === "gerador"}
      <header class="h-16 border-b border-gray-800 flex items-center px-8 bg-surface/30 backdrop-blur-sm">
        <h2 class="text-lg font-semibold text-white">Gerador de senhas</h2>
      </header>
    {:else}
      <header class="h-16 border-b border-gray-800 flex items-center justify-between px-8 bg-surface/30 backdrop-blur-sm">
        <div class="relative w-96">
          <span class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">🔍</span>
          <input
            type="text"
            bind:value={searchQuery}
            aria-label="Buscar no cofre"
            placeholder="Buscar no cofre..."
            class="w-full bg-surface border border-gray-700 text-sm rounded-full py-2 pl-10 pr-4 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder-gray-600 text-gray-200"
          />
        </div>

        <button
          onclick={novoItem}
          class="bg-primary hover:bg-primary/90 text-bg font-bold py-2 px-6 rounded-full text-sm shadow-lg shadow-primary/20 transition-transform active:scale-95 flex items-center gap-2"
        >
          <span>+</span> Novo Item
        </button>
      </header>
    {/if}

    <div class="flex-1 overflow-y-auto p-8">
      {#if activeTab === "gerador"}
        <section class="mx-auto max-w-xl space-y-6 rounded-xl border border-gray-800 bg-surface p-6">
          <div>
            <label for="password-length" class="mb-2 block text-sm font-medium text-gray-200">
              Tamanho: {generatorLength} caracteres
            </label>
            <input
              id="password-length"
              type="range"
              min={MIN_GENERATED_PASSWORD_LENGTH}
              max={MAX_GENERATED_PASSWORD_LENGTH}
              bind:value={generatorLength}
              class="w-full accent-primary"
            />
            <div class="flex justify-between text-xs text-gray-500">
              <span>{MIN_GENERATED_PASSWORD_LENGTH}</span>
              <span>{MAX_GENERATED_PASSWORD_LENGTH}</span>
            </div>
          </div>

          <fieldset class="space-y-3">
            <legend class="mb-3 text-sm font-medium text-gray-200">Tipos de caracteres</legend>
            <label class="flex items-center gap-3 text-sm text-gray-300">
              <input type="checkbox" bind:checked={generatorOptions.uppercase} class="accent-primary" />
              Letras maiúsculas (A-Z)
            </label>
            <label class="flex items-center gap-3 text-sm text-gray-300">
              <input type="checkbox" bind:checked={generatorOptions.lowercase} class="accent-primary" />
              Letras minúsculas (a-z)
            </label>
            <label class="flex items-center gap-3 text-sm text-gray-300">
              <input type="checkbox" bind:checked={generatorOptions.numbers} class="accent-primary" />
              Números (0-9)
            </label>
            <label class="flex items-center gap-3 text-sm text-gray-300">
              <input type="checkbox" bind:checked={generatorOptions.symbols} class="accent-primary" />
              Símbolos
            </label>
          </fieldset>

          <button
            onclick={generateNewPassword}
            class="w-full rounded-lg bg-primary px-4 py-2 text-sm font-bold text-bg hover:bg-primary/90"
          >
            Gerar senha
          </button>

          {#if generatedPassword}
            <div class="flex gap-2">
              <input
                aria-label="Senha gerada"
                readonly
                value={generatedPassword}
                class="min-w-0 flex-1 rounded-lg border border-gray-700 bg-bg px-3 py-2 font-mono text-sm text-gray-200"
              />
              <button
                onclick={() => copySecret(generatedPassword)}
                class="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-200 hover:bg-white/5"
              >
                Copiar
              </button>
            </div>
          {/if}

          {#if generatorError}
            <p class="text-sm text-danger">{generatorError}</p>
          {/if}
          {#if clipboardNotice}
            <p class="text-sm {clipboardNotice.startsWith('Não foi possível') ? 'text-danger' : 'text-primary'}">
              {clipboardNotice}
            </p>
          {/if}
        </section>
      {:else}
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-white">
          {activeTab === "favoritos" ? "Favoritos" : "Todas as Senhas"}
        </h2>
        <span class="text-xs text-gray-500 bg-surface px-2 py-1 rounded-md border border-gray-700">{filteredEntries.length} {filteredEntries.length === 1 ? "item" : "itens"}</span>
      </div>

      {#if listError}
        <p class="text-sm text-danger mb-4">{listError}</p>
      {/if}

      {#if clipboardNotice}
        <p class="text-sm text-primary mb-4">{clipboardNotice}</p>
      {/if}

      {#if activeTab === "favoritos" && !entries.some((entry) => entry.favorite)}
        <div class="text-center text-gray-500 text-sm py-16 border border-dashed border-gray-800 rounded-xl">
          Você ainda não adicionou itens aos favoritos.
        </div>
      {:else if entries.length === 0}
        <div class="text-center text-gray-500 text-sm py-16 border border-dashed border-gray-800 rounded-xl">
          Nenhuma senha cadastrada ainda. Clique em "Novo Item" para começar.
        </div>
      {:else if filteredEntries.length === 0}
        <div class="text-center text-gray-500 text-sm py-16 border border-dashed border-gray-800 rounded-xl">
          Nenhum item encontrado para "{searchQuery}".
        </div>
      {:else}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {#each filteredEntries as entry (entry.id)}
          <div class="bg-surface p-4 rounded-xl border border-gray-800 hover:border-primary/50 transition-all hover:shadow-lg hover:shadow-black/40">
            <div class="w-10 h-10 mb-4 rounded-full bg-primary/20 flex items-center justify-center text-xl font-bold text-primary uppercase">
              {entry.domain.charAt(0)}
            </div>
            <h3 class="font-bold text-gray-200 text-lg truncate" title={entry.domain}>{entry.domain}</h3>
            <p class="text-xs text-gray-400 mt-1 truncate">{entry.username || "Sem usuário"}</p>

            <div class="flex items-center gap-2 mt-4">
              <button
                onclick={() => copiarSenha(entry)}
                class="flex-1 text-xs py-1.5 px-2 rounded-lg border border-gray-700 text-gray-300 hover:text-white hover:bg-white/5 transition-colors"
              >
                Copiar senha
              </button>
              <button
                onclick={() => toggleFavorite(entry)}
                disabled={favoriteBusyId !== null}
                aria-label={entry.favorite ? "Remover dos favoritos" : "Adicionar aos favoritos"}
                title={entry.favorite ? "Remover dos favoritos" : "Adicionar aos favoritos"}
                class="text-lg text-primary disabled:opacity-50"
              >
                {entry.favorite ? "★" : "☆"}
              </button>
              <button
                onclick={() => editarItem(entry)}
                class="text-xs py-1.5 px-2 rounded-lg border border-gray-700 text-gray-300 hover:text-white hover:bg-white/5 transition-colors"
              >
                Editar
              </button>
              {#if deletingId === entry.id}
                <button
                  onclick={() => excluirItem(entry.id)}
                  disabled={itemBusy}
                  class="text-xs py-1.5 px-2 rounded-lg border border-danger text-danger hover:bg-danger/10 disabled:opacity-50 transition-colors"
                >
                  Confirmar
                </button>
                <button
                  onclick={() => (deletingId = null)}
                  class="text-xs py-1.5 px-2 rounded-lg border border-gray-700 text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
                >
                  Cancelar
                </button>
              {:else}
                <button
                  onclick={() => (deletingId = entry.id)}
                  class="text-xs py-1.5 px-2 rounded-lg border border-gray-700 text-gray-400 hover:text-danger hover:border-danger transition-colors"
                >
                  Excluir
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
      {/if}
      {/if}
    </div>
  </div>

  {#if modalOpen}
  <div class="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
    <form
      class="w-full max-w-md bg-surface p-6 rounded-xl border border-gray-800 space-y-4"
      onsubmit={(event) => {
        event.preventDefault();
        void salvarItem();
      }}
    >
      <h2 class="text-lg font-semibold text-white">{editingId ? "Editar Item" : "Novo Item"}</h2>

      <label class="block space-y-1">
        <span class="text-xs text-gray-400">Domínio *</span>
        <input
          type="text"
          bind:value={newDomain}
          placeholder="exemplo.com"
          required
          class="w-full bg-bg border border-gray-700 text-sm rounded-lg py-2 px-3 focus:outline-none focus:border-primary text-gray-200 placeholder-gray-600"
        />
      </label>

      <label class="block space-y-1">
        <span class="text-xs text-gray-400">Usuário</span>
        <input
          type="text"
          bind:value={newUsername}
          placeholder="meu.email@exemplo.com"
          class="w-full bg-bg border border-gray-700 text-sm rounded-lg py-2 px-3 focus:outline-none focus:border-primary text-gray-200 placeholder-gray-600"
        />
      </label>

      <label class="block space-y-1">
        <span class="text-xs text-gray-400">Senha *</span>
        <input
          type="password"
          bind:value={newPassword}
          autocomplete="new-password"
          required
          class="w-full bg-bg border border-gray-700 text-sm rounded-lg py-2 px-3 focus:outline-none focus:border-primary text-gray-200 placeholder-gray-600"
        />
      </label>

      {#if modalError}
        <p class="text-sm text-danger">{modalError}</p>
      {/if}

      <div class="flex justify-end gap-3 pt-2">
        <button
          type="button"
          onclick={fecharModal}
          class="py-2 px-4 rounded-lg text-sm text-gray-400 hover:text-white hover:bg-white/5 transition-colors"
        >
          Cancelar
        </button>
        <button
          type="submit"
          disabled={modalBusy}
          class="bg-primary hover:bg-primary/90 disabled:opacity-50 text-bg font-bold py-2 px-4 rounded-lg text-sm transition-transform active:scale-95"
        >
          Salvar
        </button>
      </div>
    </form>
  </div>
  {/if}
</main>
{/if}