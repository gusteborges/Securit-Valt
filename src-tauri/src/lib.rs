// src-tauri/src/lib.rs

// 1. Declaração dos módulos
mod domain;
mod infrastructure;
mod security;
mod application;

// 2. Importações
use application::commands::{initialize_vault, unlock_vault, add_entry, list_entries};
use security::vault_state::VaultState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // 3. Registra o estado gerenciado (chave mestra em memória para a sessão)
        .manage(VaultState::new())
        // 4. Registra os comandos disponíveis para o frontend
        .invoke_handler(tauri::generate_handler![
            initialize_vault,
            unlock_vault,
            add_entry,
            list_entries,
        ])
        .run(tauri::generate_context!())
        .expect("Erro ao iniciar a aplicação Tauri");
}
