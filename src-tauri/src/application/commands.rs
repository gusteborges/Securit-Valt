use tauri::State;
use crate::domain::models::VaultEntry;
use crate::infrastructure::database::Database;
use crate::security::{
    crypto::{derive_key_from_password, generate_salt},
    memory::SecureKey,
    vault_state::VaultState,
};

fn get_db() -> Database {
    // TODO: substituir pelo caminho resolvido via AppHandle::path_resolver()
    Database::new("securevault.db")
}

// ── Comando 1: initialize_vault ──────────────────────────────────────────────

/// Inicialização do cofre (primeira execução).
///
/// Gera um salt Argon2 aleatório, deriva a chave mestra a partir da senha
/// fornecida, persiste o salt no banco e mantém a chave em memória.
///
/// Retorna erro se o cofre já foi inicializado (salt já existe no banco).
#[tauri::command]
pub fn initialize_vault(
    password: String,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db();
    let conn = db.open_connection().map_err(|e| e.to_string())?;

    Database::setup_schema(&conn).map_err(|e| e.to_string())?;

    // Impede dupla inicialização
    if Database::get_argon2_salt(&conn)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err(
            "Cofre já inicializado. Use unlock_vault para desbloquear.".into(),
        );
    }

    // Gera e persiste o salt (gerado somente aqui, nunca recriado)
    let salt = generate_salt();
    Database::store_argon2_salt(&conn, &salt).map_err(|e| e.to_string())?;

    // Deriva a chave a partir da senha + salt
    let key_bytes = derive_key_from_password(&password, &salt)
        .map_err(|e| e.to_string())?;

    // Armazena no estado gerenciado — SecureKey zeroiza automaticamente no Drop
    let mut guard = state
        .master_key
        .lock()
        .map_err(|_| "Estado interno corrompido (mutex envenenado)")?;
    *guard = Some(SecureKey::new(key_bytes));

    Ok("Cofre inicializado e desbloqueado com sucesso.".into())
}

// ── Comando 2: unlock_vault ──────────────────────────────────────────────────

/// Desbloqueia o cofre para a sessão atual.
///
/// Carrega o salt do banco e re-deriva a chave mestra a partir da senha.
/// A derivação é determinística: mesma senha + mesmo salt = mesma chave.
///
/// Se a senha estiver errada, o erro se manifestará na primeira tentativa
/// de decriptação (AES-GCM rejeita a tag de autenticação).
#[tauri::command]
pub fn unlock_vault(
    password: String,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db();
    let conn = db.open_connection().map_err(|e| e.to_string())?;

    let salt = Database::get_argon2_salt(&conn)
        .map_err(|e| e.to_string())?
        .ok_or("Cofre não inicializado. Execute initialize_vault primeiro.")?;

    let key_bytes = derive_key_from_password(&password, &salt)
        .map_err(|e| e.to_string())?;

    let mut guard = state
        .master_key
        .lock()
        .map_err(|_| "Estado interno corrompido (mutex envenenado)")?;
    *guard = Some(SecureKey::new(key_bytes));

    Ok("Cofre desbloqueado.".into())
}

// ── Comando 3: add_entry ─────────────────────────────────────────────────────

/// Adiciona uma nova credencial ao cofre.
///
/// Requer que o cofre esteja desbloqueado (`unlock_vault` ou `initialize_vault`
/// deve ter sido chamado antes nesta sessão).
#[tauri::command]
pub fn add_entry(
    domain: String,
    username: String,
    password: String,
    state: State<VaultState>,
) -> Result<String, String> {
    // Extrai a cópia dos bytes da chave e libera o guard ANTES de qualquer I/O
    // para manter o tempo de lock mínimo.
    let key_bytes: [u8; 32] = {
        let guard = state
            .master_key
            .lock()
            .map_err(|_| "Estado interno corrompido (mutex envenenado)")?;
        *guard
            .as_ref()
            .ok_or("Cofre bloqueado. Chame unlock_vault antes de adicionar entradas.")?
            .bytes()
    }; // guard liberado aqui

    let entry = VaultEntry::new(domain, username, password);
    let db = get_db();

    db.insert_entry(&entry, &key_bytes)
        .map_err(|e| e.to_string())?;

    Ok(format!("Entrada salva com ID: {}", entry.id))
}

// ── Comando 4: list_entries ──────────────────────────────────────────────────

/// Retorna todas as entradas do cofre decriptadas.
///
/// Requer que o cofre esteja desbloqueado.
#[tauri::command]
pub fn list_entries(state: State<VaultState>) -> Result<Vec<VaultEntryResponse>, String> {
    let key_bytes: [u8; 32] = {
        let guard = state
            .master_key
            .lock()
            .map_err(|_| "Estado interno corrompido (mutex envenenado)")?;
        *guard
            .as_ref()
            .ok_or("Cofre bloqueado. Chame unlock_vault antes de listar entradas.")?
            .bytes()
    }; // guard liberado aqui

    let db = get_db();
    let entries = db
        .get_all_entries(&key_bytes)
        .map_err(|e| e.to_string())?;

    Ok(entries.into_iter().map(VaultEntryResponse::from).collect())
}

// ── DTO de resposta (serializável pelo Tauri) ────────────────────────────────

/// Estrutura de resposta retornada pelo comando `list_entries`.
///
/// Separada do modelo de domínio `VaultEntry` para evitar expor
/// campos internos via IPC e ter controle fino sobre serialização.
#[derive(serde::Serialize)]
pub struct VaultEntryResponse {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub created_at: String, // ISO 8601
}

impl From<VaultEntry> for VaultEntryResponse {
    fn from(e: VaultEntry) -> Self {
        Self {
            id: e.id,
            domain: e.domain,
            username: e.username,
            password: e.password,
            created_at: e.created_at.to_rfc3339(),
        }
    }
}
