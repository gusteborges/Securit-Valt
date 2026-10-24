use tauri::{AppHandle, Manager, State};
use crate::domain::models::VaultEntry;
use crate::infrastructure::database::Database;
use crate::security::{
    crypto::{
        derive_key_from_password, generate_salt, make_password_check,
        verify_password_check,
    },
    memory::SecureKey,
    vault_state::VaultState,
};

const MIN_PASSWORD_LEN: usize = 8;

/// Copia a chave da sessão. O guard do mutex é liberado antes de qualquer I/O.
fn session_key(state: &VaultState) -> Result<[u8; 32], String> {
    let guard = state
        .master_key
        .lock()
        .map_err(|_| "Estado interno corrompido (mutex envenenado)")?;
    let key = *guard
        .as_ref()
        .ok_or("Cofre bloqueado. Desbloqueie o cofre antes de continuar.")?
        .bytes();
    Ok(key)
}

fn validate_entry_fields(domain: &str, password: &str) -> Result<(), String> {
    if domain.trim().is_empty() || password.is_empty() {
        return Err("Domínio e senha são obrigatórios.".into());
    }
    Ok(())
}

fn get_db(app: &AppHandle) -> Result<Database, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(Database::new(dir.join("securevault.db")))
}

fn validate_master_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "A senha mestra deve ter pelo menos {MIN_PASSWORD_LEN} caracteres."
        ));
    }
    Ok(())
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
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db(&app)?;
    initialize_vault_with(&db, &state, &password)
}

fn initialize_vault_with(
    db: &Database,
    state: &VaultState,
    password: &str,
) -> Result<String, String> {
    validate_master_password(password)?;

    let mut conn = db.open_connection().map_err(|e| e.to_string())?;

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

    // Salt e verificador são gravados juntos: ou ambos existem, ou nenhum
    let salt = generate_salt();
    let key_bytes = derive_key_from_password(&password, &salt)
        .map_err(|e| e.to_string())?;
    let check = make_password_check(&key_bytes).map_err(|e| e.to_string())?;

    let tx = conn.transaction().map_err(|e| e.to_string())?;
    Database::store_argon2_salt(&tx, &salt).map_err(|e| e.to_string())?;
    Database::store_password_check(&tx, &check).map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;

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
/// Se a senha estiver errada, o verificador não confere e a chave NÃO é guardada.
/// Cofres criados antes do verificador são validados tentando decriptar as
/// entradas existentes; se o cofre estiver vazio, o verificador é criado agora.
#[tauri::command]
pub fn unlock_vault(
    password: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db(&app)?;
    unlock_vault_with(&db, &state, &password)
}

fn unlock_vault_with(
    db: &Database,
    state: &VaultState,
    password: &str,
) -> Result<String, String> {
    let conn = db.open_connection().map_err(|e| e.to_string())?;

    Database::setup_schema(&conn).map_err(|e| e.to_string())?;

    let salt = Database::get_argon2_salt(&conn)
        .map_err(|e| e.to_string())?
        .ok_or("Cofre não inicializado. Execute initialize_vault primeiro.")?;

    let key_bytes = derive_key_from_password(&password, &salt)
        .map_err(|e| e.to_string())?;

    match Database::get_password_check(&conn).map_err(|e| e.to_string())? {
        Some(blob) => {
            if !verify_password_check(&blob, &key_bytes) {
                return Err("Senha mestra incorreta.".into());
            }
        }
        None => {
            db.get_all_entries(&key_bytes)
                .map_err(|_| "Senha mestra incorreta.".to_string())?;
            let check = make_password_check(&key_bytes).map_err(|e| e.to_string())?;
            Database::store_password_check(&conn, &check).map_err(|e| e.to_string())?;
        }
    }

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
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db(&app)?;
    add_entry_with(&db, &state, domain, username, password)
}

fn add_entry_with(
    db: &Database,
    state: &VaultState,
    domain: String,
    username: String,
    password: String,
) -> Result<String, String> {
    validate_entry_fields(&domain, &password)?;
    let key_bytes = session_key(state)?;

    let entry = VaultEntry::new(domain, username, password);
    db.insert_entry(&entry, &key_bytes)
        .map_err(|e| e.to_string())?;

    Ok(format!("Entrada salva com ID: {}", entry.id))
}

// ── Comando 4: list_entries ──────────────────────────────────────────────────

/// Retorna todas as entradas do cofre decriptadas.
///
/// Requer que o cofre esteja desbloqueado.
#[tauri::command]
pub fn list_entries(
    app: AppHandle,
    state: State<VaultState>,
) -> Result<Vec<VaultEntryResponse>, String> {
    let db = get_db(&app)?;
    list_entries_with(&db, &state)
}

fn list_entries_with(
    db: &Database,
    state: &VaultState,
) -> Result<Vec<VaultEntryResponse>, String> {
    let key_bytes = session_key(state)?;

    let entries = db
        .get_all_entries(&key_bytes)
        .map_err(|e| e.to_string())?;

    Ok(entries.into_iter().map(VaultEntryResponse::from).collect())
}

// ── Comando 5: lock_vault ────────────────────────────────────────────────────

/// Bloqueia o cofre: descarta a chave mestra da memória (zeroizada pelo `Drop`).
#[tauri::command]
pub fn lock_vault(state: State<VaultState>) -> Result<String, String> {
    lock_vault_with(&state)
}

fn lock_vault_with(state: &VaultState) -> Result<String, String> {
    let mut guard = state
        .master_key
        .lock()
        .map_err(|_| "Estado interno corrompido (mutex envenenado)")?;
    *guard = None;

    Ok("Cofre bloqueado.".into())
}

// ── Comando 5: update_entry ──────────────────────────────────────────────────

/// Atualiza domain, username e password de uma entrada existente.
///
/// Requer que o cofre esteja desbloqueado.
#[tauri::command]
pub fn update_entry(
    id: String,
    domain: String,
    username: String,
    password: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db(&app)?;
    update_entry_with(&db, &state, &id, &domain, &username, &password)
}

fn update_entry_with(
    db: &Database,
    state: &VaultState,
    id: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    validate_entry_fields(domain, password)?;
    let key_bytes = session_key(state)?;

    db.update_entry(id, domain, username, password, &key_bytes)
        .map_err(|e| e.to_string())?;

    Ok("Entrada atualizada.".into())
}

// ── Comando 6: delete_entry ──────────────────────────────────────────────────

/// Remove uma entrada do cofre.
///
/// Requer que o cofre esteja desbloqueado, como as demais operações de dados.
#[tauri::command]
pub fn delete_entry(
    id: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let db = get_db(&app)?;
    delete_entry_with(&db, &state, &id)
}

fn delete_entry_with(db: &Database, state: &VaultState, id: &str) -> Result<String, String> {
    session_key(state)?;

    db.delete_entry(id).map_err(|e| e.to_string())?;

    Ok("Entrada removida.".into())
}

// ── Comando 7: vault_status ──────────────────────────────────────────────────

/// Informa se o cofre já foi inicializado e se está desbloqueado nesta sessão.
#[tauri::command]
pub fn vault_status(
    app: AppHandle,
    state: State<VaultState>,
) -> Result<VaultStatus, String> {
    let db = get_db(&app)?;
    vault_status_with(&db, &state)
}

fn vault_status_with(db: &Database, state: &VaultState) -> Result<VaultStatus, String> {
    let conn = db.open_connection().map_err(|e| e.to_string())?;

    Database::setup_schema(&conn).map_err(|e| e.to_string())?;

    let initialized = Database::get_argon2_salt(&conn)
        .map_err(|e| e.to_string())?
        .is_some();

    Ok(VaultStatus {
        initialized,
        unlocked: state.is_unlocked(),
    })
}

#[derive(serde::Serialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    const PASSWORD: &str = "senha-mestra-123";
    const WRONG_PASSWORD: &str = "senha-errada-456";

    struct Fixture {
        _dir: TempDir,
        db: Database,
        state: VaultState,
    }

    fn fixture() -> Fixture {
        let dir = TempDir::new();
        let db = dir.database();
        Fixture {
            _dir: dir,
            db,
            state: VaultState::new(),
        }
    }

    fn initialized_fixture() -> Fixture {
        let f = fixture();
        initialize_vault_with(&f.db, &f.state, PASSWORD).unwrap();
        f
    }

    fn add(f: &Fixture, domain: &str, username: &str, password: &str) {
        add_entry_with(
            &f.db,
            &f.state,
            domain.into(),
            username.into(),
            password.into(),
        )
        .unwrap();
    }

    fn password_check_stored(db: &Database) -> Option<Vec<u8>> {
        let conn = db.open_connection().unwrap();
        Database::get_password_check(&conn).unwrap()
    }

    fn remove_password_check(db: &Database) {
        let conn = db.open_connection().unwrap();
        conn.execute("DELETE FROM vault_config WHERE key = 'password_check'", [])
            .unwrap();
    }

    #[test]
    fn inicializar_deixa_o_cofre_desbloqueado() {
        let f = initialized_fixture();

        let status = vault_status_with(&f.db, &f.state).unwrap();
        assert!(status.initialized);
        assert!(status.unlocked);
    }

    #[test]
    fn senha_curta_nao_cria_cofre() {
        let f = fixture();

        assert!(initialize_vault_with(&f.db, &f.state, "curta").is_err());

        let status = vault_status_with(&f.db, &f.state).unwrap();
        assert!(!status.initialized);
        assert!(!status.unlocked);
    }

    #[test]
    fn inicializar_duas_vezes_falha() {
        let f = initialized_fixture();

        assert!(initialize_vault_with(&f.db, &f.state, PASSWORD).is_err());
    }

    #[test]
    fn bloquear_impede_adicionar_e_listar() {
        let f = initialized_fixture();

        lock_vault_with(&f.state).unwrap();

        let status = vault_status_with(&f.db, &f.state).unwrap();
        assert!(status.initialized);
        assert!(!status.unlocked);
        assert!(add_entry_with(
            &f.db,
            &f.state,
            "site.com".into(),
            "usuario".into(),
            "senha".into(),
        )
        .is_err());
        assert!(list_entries_with(&f.db, &f.state).is_err());
    }

    #[test]
    fn senha_errada_nao_desbloqueia() {
        let f = initialized_fixture();
        lock_vault_with(&f.state).unwrap();

        assert!(unlock_vault_with(&f.db, &f.state, WRONG_PASSWORD).is_err());

        assert!(!vault_status_with(&f.db, &f.state).unwrap().unlocked);
        assert!(list_entries_with(&f.db, &f.state).is_err());
    }

    #[test]
    fn senha_certa_desbloqueia_apos_bloqueio() {
        let f = initialized_fixture();
        lock_vault_with(&f.state).unwrap();

        unlock_vault_with(&f.db, &f.state, PASSWORD).unwrap();

        assert!(vault_status_with(&f.db, &f.state).unwrap().unlocked);
    }

    #[test]
    fn fluxo_completo_preserva_entradas() {
        let f = initialized_fixture();
        add(&f, "github.com", "ana", "senha-gh-1");
        add(&f, "mail.com", "ana@mail.com", "senha-mail-2");
        lock_vault_with(&f.state).unwrap();

        assert!(unlock_vault_with(&f.db, &f.state, WRONG_PASSWORD).is_err());
        unlock_vault_with(&f.db, &f.state, PASSWORD).unwrap();

        let entries = list_entries_with(&f.db, &f.state).unwrap();
        assert_eq!(entries.len(), 2);

        let github = entries.iter().find(|e| e.domain == "github.com").unwrap();
        assert_eq!(github.username, "ana");
        assert_eq!(github.password, "senha-gh-1");

        let mail = entries.iter().find(|e| e.domain == "mail.com").unwrap();
        assert_eq!(mail.username, "ana@mail.com");
        assert_eq!(mail.password, "senha-mail-2");
    }

    #[test]
    fn legado_sem_verificador_rejeita_senha_errada_sem_gravar_verificador() {
        let f = initialized_fixture();
        add(&f, "github.com", "ana", "senha-gh-1");
        lock_vault_with(&f.state).unwrap();
        remove_password_check(&f.db);

        assert!(unlock_vault_with(&f.db, &f.state, WRONG_PASSWORD).is_err());

        assert!(password_check_stored(&f.db).is_none());
        assert!(!vault_status_with(&f.db, &f.state).unwrap().unlocked);
    }

    #[test]
    fn legado_sem_verificador_aceita_senha_certa_e_grava_verificador() {
        let f = initialized_fixture();
        add(&f, "github.com", "ana", "senha-gh-1");
        lock_vault_with(&f.state).unwrap();
        remove_password_check(&f.db);

        unlock_vault_with(&f.db, &f.state, PASSWORD).unwrap();

        assert!(password_check_stored(&f.db).is_some());
        assert_eq!(list_entries_with(&f.db, &f.state).unwrap().len(), 1);
    }

    fn first_entry(f: &Fixture) -> VaultEntryResponse {
        list_entries_with(&f.db, &f.state).unwrap().remove(0)
    }

    #[test]
    fn editar_atualiza_campos_e_preserva_id_e_data() {
        let f = initialized_fixture();
        add(&f, "antigo.com", "ana", "senha-antiga");
        let before = first_entry(&f);

        update_entry_with(
            &f.db,
            &f.state,
            &before.id,
            "novo.com",
            "ana@novo.com",
            "senha-nova",
        )
        .unwrap();

        let after = first_entry(&f);
        assert_eq!(after.id, before.id);
        assert_eq!(after.created_at, before.created_at);
        assert_eq!(after.domain, "novo.com");
        assert_eq!(after.username, "ana@novo.com");
        assert_eq!(after.password, "senha-nova");
    }

    #[test]
    fn editar_entrada_inexistente_falha() {
        let f = initialized_fixture();

        assert!(update_entry_with(&f.db, &f.state, "nao-existe", "a.com", "u", "s").is_err());
    }

    #[test]
    fn editar_com_campos_obrigatorios_vazios_falha() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha");
        let entry = first_entry(&f);

        assert!(update_entry_with(&f.db, &f.state, &entry.id, "  ", "ana", "senha").is_err());
        assert!(update_entry_with(&f.db, &f.state, &entry.id, "site.com", "ana", "").is_err());
        assert_eq!(first_entry(&f).password, "senha");
    }

    #[test]
    fn editar_com_cofre_bloqueado_falha() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha");
        let entry = first_entry(&f);
        lock_vault_with(&f.state).unwrap();

        assert!(update_entry_with(&f.db, &f.state, &entry.id, "x.com", "ana", "nova").is_err());
    }

    #[test]
    fn excluir_remove_a_entrada() {
        let f = initialized_fixture();
        add(&f, "um.com", "ana", "senha-1");
        add(&f, "dois.com", "ana", "senha-2");
        let entry = list_entries_with(&f.db, &f.state)
            .unwrap()
            .into_iter()
            .find(|e| e.domain == "um.com")
            .unwrap();

        delete_entry_with(&f.db, &f.state, &entry.id).unwrap();

        let restantes = list_entries_with(&f.db, &f.state).unwrap();
        assert_eq!(restantes.len(), 1);
        assert_eq!(restantes[0].domain, "dois.com");
    }

    #[test]
    fn excluir_entrada_inexistente_falha() {
        let f = initialized_fixture();

        assert!(delete_entry_with(&f.db, &f.state, "nao-existe").is_err());
    }

    #[test]
    fn excluir_com_cofre_bloqueado_falha() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha");
        let entry = first_entry(&f);
        lock_vault_with(&f.state).unwrap();

        assert!(delete_entry_with(&f.db, &f.state, &entry.id).is_err());

        unlock_vault_with(&f.db, &f.state, PASSWORD).unwrap();
        assert_eq!(list_entries_with(&f.db, &f.state).unwrap().len(), 1);
    }
}
