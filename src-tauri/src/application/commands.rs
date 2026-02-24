use crate::domain::models::VaultEntry;
use crate::infrastructure::database::Database;
use crate::security::crypto::generate_key;

#[tauri::command]
pub fn save_password_test() -> String {
    // 1. Setup
    let db = Database::new("meu_cofre.db");
    
    // Cria tabela se não existir
    if let Ok(conn) = db.open_connection() {
        let _ = Database::setup_schema(&conn);
    }

    // 2. Chave de teste
    let master_key = generate_key(); 

    // 3. Dados fake
    let entry = VaultEntry::new(
        "google.com".to_string(),
        "meu_email@gmail.com".to_string(),
        "SenhaSuperSecreta123".to_string()
    );

    // 4. Salvar
    match db.insert_entry(&entry, &master_key) {
        Ok(_) => format!("Sucesso! Senha salva com ID: {}", entry.id),
        Err(e) => format!("Erro ao salvar: {}", e),
    }
}