// src-tauri/src/lib.rs

// 1. Declaração dos módulos
mod domain;
mod infrastructure;
mod security;
mod application;

// 2. Importação do comando (que agora vive em application/commands.rs)
use application::commands::save_password_test;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        // 3. Registra o comando importado
        .invoke_handler(tauri::generate_handler![save_password_test]) 
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}