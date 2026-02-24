<script lang="ts">
  import "../routes/app.css"; 
  import { invoke } from "@tauri-apps/api/core";

  let activeTab = "cofre";

  // Função placeholder para quando clicarmos no botão
  function novoItem() {
    alert("Em breve: Modal para adicionar senha!");
  }
</script>

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
        on:click={() => activeTab = 'cofre'}
      >
        <span>🔐</span> Todos os Itens
      </button>

      <button 
        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors
        {activeTab === 'favoritos' ? 'bg-primary/10 text-primary' : 'text-gray-400 hover:bg-white/5 hover:text-white'}"
        on:click={() => activeTab = 'favoritos'}
      >
        <span>⭐</span> Favoritos
      </button>

      <button 
        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors
        {activeTab === 'gerador' ? 'bg-primary/10 text-primary' : 'text-gray-400 hover:bg-white/5 hover:text-white'}"
        on:click={() => activeTab = 'gerador'}
      >
        <span>⚡</span> Gerador
      </button>
    </nav>

    <div class="p-4 border-t border-gray-800">
      <button class="w-full flex items-center gap-3 px-4 py-2 text-sm text-gray-500 hover:text-danger transition-colors">
        <span>🚪</span> Bloquear Cofre
      </button>
    </div>
  </aside>

  <div class="flex-1 flex flex-col h-full bg-bg">
    
    <header class="h-16 border-b border-gray-800 flex items-center justify-between px-8 bg-surface/30 backdrop-blur-sm">
      <div class="relative w-96">
        <span class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">🔍</span>
        <input 
          type="text" 
          placeholder="Buscar no cofre..." 
          class="w-full bg-surface border border-gray-700 text-sm rounded-full py-2 pl-10 pr-4 focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all placeholder-gray-600 text-gray-200"
        />
      </div>

      <button 
        on:click={novoItem}
        class="bg-primary hover:bg-primary/90 text-bg font-bold py-2 px-6 rounded-full text-sm shadow-lg shadow-primary/20 transition-transform active:scale-95 flex items-center gap-2"
      >
        <span>+</span> Novo Item
      </button>
    </header>

    <div class="flex-1 overflow-y-auto p-8">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-xl font-semibold text-white">Todas as Senhas</h2>
        <span class="text-xs text-gray-500 bg-surface px-2 py-1 rounded-md border border-gray-700">3 itens</span>
      </div>
      
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        
        <div class="bg-surface p-4 rounded-xl border border-gray-800 hover:border-primary/50 cursor-pointer transition-all hover:shadow-lg hover:shadow-black/40 group relative">
          <div class="flex justify-between mb-4">
            <div class="w-10 h-10 rounded-full bg-white flex items-center justify-center text-xl font-bold text-gray-800">
              G
            </div>
            <button class="text-gray-500 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity" title="Copiar Senha">
              📋
            </button>
          </div>
          <h3 class="font-bold text-gray-200 text-lg">Google</h3>
          <p class="text-xs text-gray-400 mt-1">meu.email@gmail.com</p>
        </div>

        <div class="bg-surface p-4 rounded-xl border border-gray-800 hover:border-primary/50 cursor-pointer transition-all hover:shadow-lg hover:shadow-black/40 group relative">
          <div class="flex justify-between mb-4">
            <div class="w-10 h-10 rounded-full bg-[#1877F2] flex items-center justify-center text-xl font-bold text-white">
              f
            </div>
            <button class="text-gray-500 hover:text-white opacity-0 group-hover:opacity-100 transition-opacity">
              📋
            </button>
          </div>
          <h3 class="font-bold text-gray-200 text-lg">Facebook</h3>
          <p class="text-xs text-gray-400 mt-1">social@meta.com</p>
        </div>

      </div>
    </div>
  </div>
</main>