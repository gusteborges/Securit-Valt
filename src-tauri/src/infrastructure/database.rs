// src-tauri/src/infrastructure/database.rs

use rusqlite::{params, Connection, Result};
use std::path::Path;
use crate::domain::models::VaultEntry;
use crate::security::crypto::{decrypt, encrypt, ARGON2_SALT_LEN};

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

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;

        Ok(conn)
    }

    // ── Sistema de Migrações ─────────────────────────────────────────────────

    /// Aplica todas as migrações pendentes de forma idempotente.
    /// Usa `PRAGMA user_version` como número de versão do schema.
    pub fn setup_schema(conn: &Connection) -> Result<()> {
        let current_version: i32 =
            conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        // Migration v1 — tabela inicial vault_entries (schema legado, sem nonce_username)
        // Só aplicada se o banco já existia com user_version = 0 e a tabela foi criada
        // manualmente fora do sistema de migrações. Bancos novos pulam direto para v2.
        if current_version < 1 {
            println!("🔄 Aplicando Migration v1: Criando tabelas iniciais (schema legado)...");

            // Cria com o schema legado somente se a tabela ainda não existir
            // (bancos novos serão criados diretamente com o schema v2 abaixo)
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS vault_entries (
                    id                 TEXT PRIMARY KEY,
                    domain             TEXT NOT NULL,
                    username_encrypted BLOB,
                    password_encrypted BLOB NOT NULL,
                    nonce              BLOB NOT NULL,
                    created_at         TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_domain ON vault_entries (domain);",
            )?;

            conn.execute_batch("PRAGMA user_version = 1")?;
            println!("✅ Migration v1 concluída.");
        }

        // Migration v2 — vault_config (salt Argon2) + schema vault_entries correto
        if current_version < 2 {
            println!("🔄 Aplicando Migration v2: vault_config + nonce_username...");

            // Tabela de configuração do cofre (salt Argon2, versão de schema, etc.)
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS vault_config (
                    key   TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );",
            )?;

            // Verifica se vault_entries já existe (banco legado com coluna 'nonce')
            let old_col_exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('vault_entries')
                     WHERE name = 'nonce'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap_or(0)
                > 0;

            if old_col_exists {
                // Banco legado: renomeia 'nonce' → 'nonce_password' e adiciona 'nonce_username'
                // via reconstrução de tabela (SQLite não tem RENAME COLUMN antes de 3.25)
                conn.execute_batch(
                    "BEGIN;
                     CREATE TABLE vault_entries_new (
                         id                 TEXT PRIMARY KEY,
                         domain             TEXT NOT NULL,
                         username_encrypted BLOB,
                         nonce_username     BLOB,
                         password_encrypted BLOB NOT NULL,
                         nonce_password     BLOB NOT NULL,
                         created_at         TEXT NOT NULL
                     );
                     INSERT INTO vault_entries_new
                         SELECT id, domain, username_encrypted, NULL,
                                password_encrypted, nonce AS nonce_password, created_at
                         FROM vault_entries;
                     DROP TABLE vault_entries;
                     ALTER TABLE vault_entries_new RENAME TO vault_entries;
                     CREATE INDEX IF NOT EXISTS idx_domain ON vault_entries (domain);
                     COMMIT;",
                )?;
            } else {
                // Banco novo (nunca teve v1 ou tabela ainda não existe): cria com schema correto
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS vault_entries (
                         id                 TEXT PRIMARY KEY,
                         domain             TEXT NOT NULL,
                         username_encrypted BLOB,
                         nonce_username     BLOB,
                         password_encrypted BLOB NOT NULL,
                         nonce_password     BLOB NOT NULL,
                         created_at         TEXT NOT NULL
                     );
                     CREATE INDEX IF NOT EXISTS idx_domain ON vault_entries (domain);",
                )?;
            }

            conn.execute_batch("PRAGMA user_version = 2")?;
            println!("✅ Migration v2 concluída.");
        }

        Ok(())
    }

    // ── Persistência do Salt Argon2 ──────────────────────────────────────────

    /// Lê o salt Argon2 do banco. Retorna `None` se o cofre nunca foi inicializado.
    pub fn get_argon2_salt(
        conn: &Connection,
    ) -> Result<Option<[u8; ARGON2_SALT_LEN]>> {
        let result = conn.query_row(
            "SELECT value FROM vault_config WHERE key = 'argon2_salt'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        );

        match result {
            Ok(bytes) => {
                let arr: [u8; ARGON2_SALT_LEN] = bytes
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidColumnType(
                        0,
                        "argon2_salt".into(),
                        rusqlite::types::Type::Blob,
                    ))?;
                Ok(Some(arr))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Persiste o salt Argon2 gerado na inicialização do cofre.
    /// Deve ser chamado somente uma vez — `initialize_vault` garante isso.
    pub fn store_argon2_salt(
        conn: &Connection,
        salt: &[u8; ARGON2_SALT_LEN],
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO vault_config (key, value) VALUES ('argon2_salt', ?1)",
            params![salt.as_ref()],
        )?;
        Ok(())
    }

    /// Lê o verificador de senha mestra. `None` em cofres criados antes do verificador.
    pub fn get_password_check(conn: &Connection) -> Result<Option<Vec<u8>>> {
        match conn.query_row(
            "SELECT value FROM vault_config WHERE key = 'password_check'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Persiste o verificador de senha mestra (ver `crypto::make_password_check`).
    pub fn store_password_check(conn: &Connection, blob: &[u8]) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO vault_config (key, value) VALUES ('password_check', ?1)",
            params![blob],
        )?;
        Ok(())
    }

    // ── Escrita ──────────────────────────────────────────────────────────────

    /// Encripta e salva uma entrada no cofre.
    ///
    /// Cada campo (username, password) recebe seu próprio nonce aleatório.
    /// Ambos os nonces são persistidos — correção do bug original que descartava
    /// o nonce do username (`_nonce_user`).
    pub fn insert_entry(
        &self,
        entry: &VaultEntry,
        master_key: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.open_connection()?;

        // Cada campo usa um nonce independente — reutilização de nonce com a
        // mesma chave em GCM quebra a confidencialidade de ambos os registros.
        let (enc_password, nonce_password) = encrypt(&entry.password, master_key)?;
        let (enc_username, nonce_username) = encrypt(&entry.username, master_key)?;

        conn.execute(
            "INSERT INTO vault_entries
             (id, domain, username_encrypted, nonce_username,
              password_encrypted, nonce_password, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.id,
                entry.domain,
                enc_username,
                nonce_username,   // antes descartado como `_nonce_user` — agora persistido
                enc_password,
                nonce_password,
                entry.created_at.to_rfc3339()
            ],
        )?;

        Ok(())
    }

    /// Substitui domain, username e password de uma entrada existente.
    ///
    /// Gera novos nonces para os campos cifrados e preserva `id` e `created_at`.
    /// Falha se a entrada não existir.
    pub fn update_entry(
        &self,
        id: &str,
        domain: &str,
        username: &str,
        password: &str,
        master_key: &[u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.open_connection()?;

        let (enc_password, nonce_password) = encrypt(password, master_key)?;
        let (enc_username, nonce_username) = encrypt(username, master_key)?;

        let updated = conn.execute(
            "UPDATE vault_entries
             SET domain = ?2,
                 username_encrypted = ?3, nonce_username = ?4,
                 password_encrypted = ?5, nonce_password = ?6
             WHERE id = ?1",
            params![
                id,
                domain,
                enc_username,
                nonce_username,
                enc_password,
                nonce_password
            ],
        )?;

        if updated == 0 {
            return Err("Entrada não encontrada.".into());
        }
        Ok(())
    }

    /// Remove uma entrada pelo id. Falha se a entrada não existir.
    pub fn delete_entry(&self, id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let conn = self.open_connection()?;

        let deleted = conn.execute("DELETE FROM vault_entries WHERE id = ?1", params![id])?;

        if deleted == 0 {
            return Err("Entrada não encontrada.".into());
        }
        Ok(())
    }

    // ── Leitura ──────────────────────────────────────────────────────────────

    /// Lê e decripta todas as entradas do cofre.
    ///
    /// Entradas legadas (migradas da v1) com `nonce_username = NULL` retornam
    /// o campo username como `"[indisponível — registro legado]"` em vez de
    /// falhar e bloquear acesso a todos os dados.
    pub fn get_all_entries(
        &self,
        master_key: &[u8; 32],
    ) -> Result<Vec<VaultEntry>, Box<dyn std::error::Error>> {
        let conn = self.open_connection()?;

        let mut stmt = conn.prepare(
            "SELECT id, domain,
                    username_encrypted, nonce_username,
                    password_encrypted, nonce_password,
                    created_at
             FROM vault_entries
             ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,        // id
                row.get::<_, String>(1)?,        // domain
                row.get::<_, Option<Vec<u8>>>(2)?, // username_encrypted
                row.get::<_, Option<Vec<u8>>>(3)?, // nonce_username
                row.get::<_, Vec<u8>>(4)?,       // password_encrypted
                row.get::<_, Vec<u8>>(5)?,       // nonce_password
                row.get::<_, String>(6)?,        // created_at
            ))
        })?;

        let mut entries = Vec::new();

        for raw in rows {
            let (id, domain, enc_username, nonce_username,
                 enc_password, nonce_password, created_at_str) = raw?;

            // Decripta a senha — falha explícita em caso de chave errada ou corrupção
            let password = decrypt(&enc_password, &nonce_password, master_key)
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("Erro ao decriptar senha do registro '{id}': {e}").into()
                })?;

            // Decripta o username — degradação graciosa para registros legados
            let username = match (enc_username, nonce_username) {
                (Some(enc), Some(nonce)) => {
                    decrypt(&enc, &nonce, master_key)
                        .map_err(|e| -> Box<dyn std::error::Error> {
                            format!("Erro ao decriptar username do registro '{id}': {e}").into()
                        })?
                }
                _ => "[indisponível — registro legado]".to_string(),
            };

            let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| -> Box<dyn std::error::Error> {
                    format!("Data inválida no registro '{id}': {e}").into()
                })?
                .with_timezone(&chrono::Utc);

            entries.push(VaultEntry {
                id,
                domain,
                username,
                password,
                created_at,
            });
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::encrypt;
    use crate::test_support::TempDir;

    const KEY: [u8; 32] = [42u8; 32];
    const OTHER_KEY: [u8; 32] = [43u8; 32];

    fn schema_version(conn: &Connection) -> i32 {
        conn.query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    fn column_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap();
        stmt.query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    fn sample_entry(domain: &str) -> VaultEntry {
        VaultEntry::new(
            domain.to_string(),
            "usuario@exemplo.com".to_string(),
            "senha-forte".to_string(),
        )
    }

    /// Banco com o schema atual já aplicado.
    fn migrated_db() -> (TempDir, Database) {
        let dir = TempDir::new();
        let db = dir.database();
        let conn = db.open_connection().unwrap();
        Database::setup_schema(&conn).unwrap();
        (dir, db)
    }

    #[test]
    fn banco_novo_nasce_na_versao_2_com_schema_atual() {
        let (_dir, db) = migrated_db();
        let conn = db.open_connection().unwrap();

        assert_eq!(schema_version(&conn), 2);

        let columns = column_names(&conn, "vault_entries");
        for expected in [
            "id",
            "domain",
            "username_encrypted",
            "nonce_username",
            "password_encrypted",
            "nonce_password",
            "created_at",
        ] {
            assert!(
                columns.iter().any(|c| c == expected),
                "coluna ausente: {expected}"
            );
        }
        assert!(!columns.iter().any(|c| c == "nonce"));
        assert!(!column_names(&conn, "vault_config").is_empty());
    }

    #[test]
    fn migra_schema_legado_preservando_dados() {
        let dir = TempDir::new();
        let db = dir.database();
        let conn = db.open_connection().unwrap();

        // Schema v0: coluna única `nonce` para a senha, sem nonce do username.
        let (enc_password, nonce_password) = encrypt("senha-antiga", &KEY).unwrap();
        conn.execute_batch(
            "CREATE TABLE vault_entries (
                id                 TEXT PRIMARY KEY,
                domain             TEXT NOT NULL,
                username_encrypted BLOB,
                password_encrypted BLOB NOT NULL,
                nonce              BLOB NOT NULL,
                created_at         TEXT NOT NULL
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO vault_entries
             (id, domain, username_encrypted, password_encrypted, nonce, created_at)
             VALUES ('legado-1', 'antigo.com', NULL, ?1, ?2, '2024-01-01T00:00:00+00:00')",
            params![enc_password, nonce_password],
        )
        .unwrap();

        Database::setup_schema(&conn).unwrap();

        assert_eq!(schema_version(&conn), 2);
        let columns = column_names(&conn, "vault_entries");
        assert!(!columns.iter().any(|c| c == "nonce"));
        assert!(columns.iter().any(|c| c == "nonce_username"));

        let entries = db.get_all_entries(&KEY).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "legado-1");
        assert_eq!(entries[0].domain, "antigo.com");
        assert_eq!(entries[0].password, "senha-antiga");
        assert_eq!(entries[0].username, "[indisponível — registro legado]");
    }

    #[test]
    fn setup_schema_e_idempotente() {
        let (_dir, db) = migrated_db();
        db.insert_entry(&sample_entry("site.com"), &KEY).unwrap();

        let conn = db.open_connection().unwrap();
        Database::setup_schema(&conn).unwrap();
        Database::setup_schema(&conn).unwrap();

        assert_eq!(schema_version(&conn), 2);
        assert_eq!(db.get_all_entries(&KEY).unwrap().len(), 1);
    }

    #[test]
    fn insert_e_get_preservam_os_campos() {
        let (_dir, db) = migrated_db();
        let entry = sample_entry("github.com");

        db.insert_entry(&entry, &KEY).unwrap();
        let entries = db.get_all_entries(&KEY).unwrap();

        assert_eq!(entries.len(), 1);
        let stored = &entries[0];
        assert_eq!(stored.id, entry.id);
        assert_eq!(stored.domain, "github.com");
        assert_eq!(stored.username, "usuario@exemplo.com");
        assert_eq!(stored.password, "senha-forte");
        assert_eq!(stored.created_at, entry.created_at);
    }

    #[test]
    fn get_com_chave_errada_falha() {
        let (_dir, db) = migrated_db();
        db.insert_entry(&sample_entry("site.com"), &KEY).unwrap();

        assert!(db.get_all_entries(&OTHER_KEY).is_err());
    }

    #[test]
    fn salt_so_pode_ser_gravado_uma_vez() {
        let (_dir, db) = migrated_db();
        let conn = db.open_connection().unwrap();
        assert!(Database::get_argon2_salt(&conn).unwrap().is_none());

        let salt = [5u8; ARGON2_SALT_LEN];
        Database::store_argon2_salt(&conn, &salt).unwrap();
        assert_eq!(Database::get_argon2_salt(&conn).unwrap(), Some(salt));

        assert!(Database::store_argon2_salt(&conn, &[6u8; ARGON2_SALT_LEN]).is_err());
    }

    #[test]
    fn verificador_de_senha_e_persistido() {
        let (_dir, db) = migrated_db();
        let conn = db.open_connection().unwrap();
        assert!(Database::get_password_check(&conn).unwrap().is_none());

        Database::store_password_check(&conn, &[1, 2, 3]).unwrap();
        assert_eq!(
            Database::get_password_check(&conn).unwrap(),
            Some(vec![1, 2, 3])
        );
    }
}

