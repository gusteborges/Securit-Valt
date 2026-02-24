// src-tauri/src/infrastructure/database.rs

use rusqlite::{params, Connection, Result};
use std::path::Path;
use crate::domain::models::VaultEntry;
use crate::security::crypto::encrypt; 

pub struct Database {
    path: String,
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_string_lossy().to_string(),
        }
    }

    pub fn open_connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        
        // O execute_batch ignora os retornos, resolvendo o erro do "journal_mode"
        conn.execute_batch(
        "PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;"
        )?;
        
        Ok(conn)
    }

    // --- MIGRATION SYSTEM (A parte Inteligente) ---
    pub fn setup_schema(conn: &Connection) -> Result<()> {
        // 1. Verifica a versão atual do banco
        let current_version: i32 = conn.query_row(
            "PRAGMA user_version",
            [],
            |row| row.get(0)
        )?;

        // 2. Se for menor que 1, aplica a criação inicial
        if current_version < 1 {
            println!("🔄 Aplicando Migration v1: Criando tabelas iniciais...");
            
            conn.execute(
                "CREATE TABLE IF NOT EXISTS vault_entries (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    username_encrypted BLOB, -- BLOB para guardar bytes criptografados
                    password_encrypted BLOB NOT NULL,
                    nonce BLOB NOT NULL,     -- O 'sal' aleatório usado na encriptação
                    created_at TEXT NOT NULL
                )",
                [],
            )?;

            // Cria índice para busca rápida por site (ex: google.com)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_domain ON vault_entries (domain)",
                [],
            )?;

            // Atualiza a versão para não rodar isso de novo
            conn.execute("PRAGMA user_version = 1", [])?;
            println!("✅ Migration v1 concluída.");
        }

        Ok(())
    }

    pub fn insert_entry(&self, entry: &VaultEntry, master_key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.open_connection()?;

        // 1. Encripta a SENHA
        // Retorna 
        let (enc_password, nonce_pass) = encrypt(&entry.password, master_key)?;
        
        // 2. Encripta o USUÁRIO 
        let (enc_username, _nonce_user) = encrypt(&entry.username, master_key)?;

        // 3. Salva no SQLite
        conn.execute(
            "INSERT INTO vault_entries (id, domain, username_encrypted, password_encrypted, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.id,
                entry.domain,
                enc_username, 
                enc_password, 
                nonce_pass,   // Importante: nonce para ler a senha depois
                entry.created_at.to_rfc3339()
            ],
        )?;

        Ok(())
    }
}