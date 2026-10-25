use crate::domain::{errors::AppError, models::VaultEntry};
use crate::infrastructure::database::Database;
use crate::security::{
    crypto::{derive_key_from_password, generate_salt, make_password_check, verify_password_check},
    memory::SecureKey,
    vault_state::VaultState,
};
use rusqlite::Connection;
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroize;

const MIN_PASSWORD_LEN: usize = 8;

/// Copia a chave da sessão. O guard do mutex é liberado antes de qualquer I/O.
fn session_key(state: &VaultState) -> Result<SecureKey, AppError> {
    let guard = state
        .master_key
        .lock()
        .map_err(|_| AppError::Internal("Estado interno corrompido (mutex envenenado)".into()))?;
    let mut key = *guard.as_ref().ok_or(AppError::VaultLocked)?.bytes();
    let secure_key = SecureKey::new(key);
    key.zeroize();
    Ok(secure_key)
}

fn validate_entry_fields(domain: &str, password: &str) -> Result<(), AppError> {
    if domain.trim().is_empty() || password.is_empty() {
        return Err(AppError::Validation(
            "Domínio e senha são obrigatórios.".into(),
        ));
    }
    Ok(())
}

fn get_db(app: &AppHandle) -> Result<Database, AppError> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Platform(e.to_string()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(Database::new(dir.join("securevault.db")))
}

fn validate_master_password(password: &str) -> Result<(), AppError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::Validation(format!(
            "A senha mestra deve ter pelo menos {MIN_PASSWORD_LEN} caracteres."
        )));
    }
    Ok(())
}

// ── Comando 1: initialize_vault ──────────────────────────────────────────────

/// Um cofre está inicializado quando há salt e (verificador ou entradas).
///
/// Salt sem verificador e sem entradas é o resto de um cofre legado vazio: não
/// guarda dados, então é tratado como não inicializado e recriado com a senha
/// escolhida no setup, em vez de aceitar a primeira senha digitada no desbloqueio.
fn vault_is_initialized(conn: &Connection) -> Result<bool, AppError> {
    let has_salt = Database::get_argon2_salt(conn)?.is_some();
    if !has_salt {
        return Ok(false);
    }

    let has_check = Database::get_password_check(conn)?.is_some();
    if has_check {
        return Ok(true);
    }

    Database::has_entries(conn).map_err(AppError::Database)
}

/// Inicialização do cofre (primeira execução).
///
/// Gera um salt Argon2 aleatório, deriva a chave mestra a partir da senha
/// fornecida, persiste o salt no banco e mantém a chave em memória.
///
/// Retorna erro se o cofre já foi inicializado.
#[tauri::command]
pub fn initialize_vault(
    mut password: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let result = get_db(&app).and_then(|db| initialize_vault_with(&db, &state, &password));
    password.zeroize();
    result.map_err(|e| e.to_string())
}

fn initialize_vault_with(
    db: &Database,
    state: &VaultState,
    password: &str,
) -> Result<String, AppError> {
    validate_master_password(password)?;

    let mut conn = db.open_connection()?;

    Database::setup_schema(&conn)?;

    // Impede dupla inicialização e nunca recria sobre entradas existentes
    let has_entries = Database::has_entries(&conn)?;
    if vault_is_initialized(&conn)? || has_entries {
        return Err(AppError::VaultAlreadyInitialized);
    }

    // Salt e verificador são gravados juntos: ou ambos existem, ou nenhum
    let salt = generate_salt();
    let key =
        derive_key_from_password(password, &salt).map_err(|e| AppError::Crypto(e.to_string()))?;
    let check = make_password_check(key.bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;

    let tx = conn.transaction()?;
    Database::clear_vault_config(&tx)?;
    Database::store_argon2_salt(&tx, &salt)?;
    Database::store_password_check(&tx, &check)?;
    tx.commit()?;

    // Armazena no estado gerenciado — SecureKey zeroiza automaticamente no Drop
    let mut guard = state
        .master_key
        .lock()
        .map_err(|_| AppError::Internal("Estado interno corrompido (mutex envenenado)".into()))?;
    *guard = Some(key);

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
/// entradas existentes; nesse caso o verificador é gravado. Um cofre sem
/// verificador e sem entradas não é desbloqueável: deve ser recriado por
/// `initialize_vault`.
#[tauri::command]
pub fn unlock_vault(
    mut password: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let result = get_db(&app).and_then(|db| unlock_vault_with(&db, &state, &password));
    password.zeroize();
    result.map_err(|e| e.to_string())
}

fn unlock_vault_with(
    db: &Database,
    state: &VaultState,
    password: &str,
) -> Result<String, AppError> {
    let conn = db.open_connection()?;

    Database::setup_schema(&conn)?;

    if !vault_is_initialized(&conn)? {
        return Err(AppError::VaultNotInitialized);
    }

    let salt = Database::get_argon2_salt(&conn)
        .map_err(AppError::Database)?
        .ok_or(AppError::VaultNotInitialized)?;

    let key =
        derive_key_from_password(password, &salt).map_err(|e| AppError::Crypto(e.to_string()))?;

    match Database::get_password_check(&conn)? {
        Some(blob) => {
            if !verify_password_check(&blob, key.bytes()) {
                return Err(AppError::IncorrectMasterPassword);
            }
        }
        None => {
            let mut entries = db
                .get_all_entries(key.bytes())
                .map_err(|_| AppError::IncorrectMasterPassword)?;
            for entry in &mut entries {
                entry.password.zeroize();
                entry.username.zeroize();
            }
            let check =
                make_password_check(key.bytes()).map_err(|e| AppError::Crypto(e.to_string()))?;
            Database::store_password_check(&conn, &check)?;
        }
    }

    let mut guard = state
        .master_key
        .lock()
        .map_err(|_| AppError::Internal("Estado interno corrompido (mutex envenenado)".into()))?;
    *guard = Some(key);

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
    mut username: String,
    mut password: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let result =
        get_db(&app).and_then(|db| add_entry_with(&db, &state, &domain, &username, &password));
    username.zeroize();
    password.zeroize();
    result.map_err(|e| e.to_string())
}

fn add_entry_with(
    db: &Database,
    state: &VaultState,
    domain: &str,
    username: &str,
    password: &str,
) -> Result<String, AppError> {
    validate_entry_fields(domain, password)?;
    let key = session_key(state)?;

    let entry = VaultEntry::new(
        domain.to_string(),
        username.to_string(),
        password.to_string(),
    );
    db.insert_entry(&entry, key.bytes())
        .map_err(|e| AppError::Persistence(e.to_string()))?;

    Ok(format!("Entrada salva com ID: {}", entry.id))
}

// ── Comando 4: list_entries ──────────────────────────────────────────────────

/// Retorna os metadados de todas as entradas (sem senha).
///
/// As senhas não trafegam nesta listagem: use `get_password` sob demanda.
/// Requer que o cofre esteja desbloqueado.
#[tauri::command]
pub fn list_entries(
    app: AppHandle,
    state: State<VaultState>,
) -> Result<Vec<VaultEntrySummary>, String> {
    get_db(&app)
        .and_then(|db| list_entries_with(&db, &state))
        .map_err(|e| e.to_string())
}

fn list_entries_with(
    db: &Database,
    state: &VaultState,
) -> Result<Vec<VaultEntrySummary>, AppError> {
    let key = session_key(state)?;

    let entries = db
        .get_all_entries(key.bytes())
        .map_err(|e| AppError::Persistence(e.to_string()))?;

    Ok(entries.iter().map(VaultEntrySummary::from).collect())
}

// ── Comando 4b: get_password ─────────────────────────────────────────────────

/// Retorna a senha de uma entrada, decriptada sob demanda.
///
/// Requer que o cofre esteja desbloqueado.
#[tauri::command]
pub fn get_password(
    id: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    get_db(&app)
        .and_then(|db| get_password_with(&db, &state, &id))
        .map_err(|e| e.to_string())
}

fn get_password_with(db: &Database, state: &VaultState, id: &str) -> Result<String, AppError> {
    let key = session_key(state)?;

    db.get_entry_password(id, key.bytes())
        .map_err(|e| AppError::Persistence(e.to_string()))?
        .ok_or(AppError::EntryNotFound)
}

// ── Comando 5: lock_vault ────────────────────────────────────────────────────

/// Bloqueia o cofre: descarta a chave mestra da memória (zeroizada pelo `Drop`).
#[tauri::command]
pub fn lock_vault(state: State<VaultState>) -> Result<String, String> {
    lock_vault_with(&state).map_err(|e| e.to_string())
}

fn lock_vault_with(state: &VaultState) -> Result<String, AppError> {
    let mut guard = state
        .master_key
        .lock()
        .map_err(|_| AppError::Internal("Estado interno corrompido (mutex envenenado)".into()))?;
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
    mut username: String,
    mut password: String,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    let result = get_db(&app)
        .and_then(|db| update_entry_with(&db, &state, &id, &domain, &username, &password));
    username.zeroize();
    password.zeroize();
    result.map_err(|e| e.to_string())
}

fn update_entry_with(
    db: &Database,
    state: &VaultState,
    id: &str,
    domain: &str,
    username: &str,
    password: &str,
) -> Result<String, AppError> {
    validate_entry_fields(domain, password)?;
    let key = session_key(state)?;

    db.update_entry(id, domain, username, password, key.bytes())
        .map_err(|e| AppError::Persistence(e.to_string()))?;

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
    get_db(&app)
        .and_then(|db| delete_entry_with(&db, &state, &id))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_favorite(
    id: String,
    favorite: bool,
    app: AppHandle,
    state: State<VaultState>,
) -> Result<String, String> {
    get_db(&app)
        .and_then(|db| set_favorite_with(&db, &state, &id, favorite))
        .map_err(|e| e.to_string())
}

fn set_favorite_with(
    db: &Database,
    state: &VaultState,
    id: &str,
    favorite: bool,
) -> Result<String, AppError> {
    let _key = session_key(state)?;

    db.set_favorite(id, favorite)
        .map_err(|e| AppError::Persistence(e.to_string()))?;

    Ok("Favorito atualizado.".into())
}

fn delete_entry_with(db: &Database, state: &VaultState, id: &str) -> Result<String, AppError> {
    let _key = session_key(state)?;

    db.delete_entry(id)
        .map_err(|e| AppError::Persistence(e.to_string()))?;

    Ok("Entrada removida.".into())
}

// ── Comando 7: vault_status ──────────────────────────────────────────────────

/// Informa se o cofre já foi inicializado e se está desbloqueado nesta sessão.
#[tauri::command]
pub fn vault_status(app: AppHandle, state: State<VaultState>) -> Result<VaultStatus, String> {
    get_db(&app)
        .and_then(|db| vault_status_with(&db, &state))
        .map_err(|e| e.to_string())
}

fn vault_status_with(db: &Database, state: &VaultState) -> Result<VaultStatus, AppError> {
    let conn = db.open_connection()?;

    Database::setup_schema(&conn)?;

    let initialized = vault_is_initialized(&conn)?;

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

/// Metadados de uma entrada, retornados por `list_entries`. A senha não faz parte
/// deste DTO: ela é obtida com `get_password`.
///
/// Separada do modelo de domínio `VaultEntry` para evitar expor
/// campos internos via IPC e ter controle fino sobre serialização.
#[derive(serde::Serialize)]
pub struct VaultEntrySummary {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub created_at: String, // ISO 8601
    pub favorite: bool,
}

impl From<&VaultEntry> for VaultEntrySummary {
    fn from(e: &VaultEntry) -> Self {
        Self {
            id: e.id.clone(),
            domain: e.domain.clone(),
            username: e.username.clone(),
            created_at: e.created_at.to_rfc3339(),
            favorite: e.favorite,
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
        add_entry_with(&f.db, &f.state, domain, username, password).unwrap();
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

        assert!(matches!(
            validate_master_password("curta"),
            Err(AppError::Validation(_))
        ));
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
        assert!(matches!(
            add_entry_with(&f.db, &f.state, "site.com", "usuario", "senha"),
            Err(AppError::VaultLocked)
        ));
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
        assert_eq!(
            get_password_with(&f.db, &f.state, &github.id).unwrap(),
            "senha-gh-1"
        );

        let mail = entries.iter().find(|e| e.domain == "mail.com").unwrap();
        assert_eq!(mail.username, "ana@mail.com");
        assert_eq!(
            get_password_with(&f.db, &f.state, &mail.id).unwrap(),
            "senha-mail-2"
        );
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

    fn first_entry(f: &Fixture) -> VaultEntrySummary {
        list_entries_with(&f.db, &f.state).unwrap().remove(0)
    }

    #[test]
    fn listagem_serializa_metadados_sem_campo_de_senha() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha-secreta");
        let entry = first_entry(&f);

        let response = serde_json::to_value(entry).unwrap();

        assert_eq!(response["domain"], "site.com");
        assert_eq!(response["username"], "ana");
        assert_eq!(response["favorite"], false);
        assert!(response.get("password").is_none());
    }

    #[test]
    fn favorito_pode_ser_alterado_e_requer_cofre_desbloqueado() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha-site");
        let entry = first_entry(&f);

        set_favorite_with(&f.db, &f.state, &entry.id, true).unwrap();
        assert!(first_entry(&f).favorite);

        lock_vault_with(&f.state).unwrap();
        assert!(set_favorite_with(&f.db, &f.state, &entry.id, false).is_err());
    }

    #[test]
    fn favorito_de_entrada_inexistente_falha() {
        let f = initialized_fixture();

        assert!(set_favorite_with(&f.db, &f.state, "nao-existe", true).is_err());
    }

    fn password_of(f: &Fixture, id: &str) -> String {
        get_password_with(&f.db, &f.state, id).unwrap()
    }

    #[test]
    fn legado_vazio_sem_verificador_nao_esta_inicializado() {
        let f = initialized_fixture();
        lock_vault_with(&f.state).unwrap();
        remove_password_check(&f.db);

        assert!(!vault_status_with(&f.db, &f.state).unwrap().initialized);
        assert!(unlock_vault_with(&f.db, &f.state, PASSWORD).is_err());
    }

    #[test]
    fn legado_vazio_pode_ser_recriado_com_senha_confirmada() {
        let f = initialized_fixture();
        lock_vault_with(&f.state).unwrap();
        remove_password_check(&f.db);

        initialize_vault_with(&f.db, &f.state, "nova-senha-789").unwrap();
        lock_vault_with(&f.state).unwrap();

        assert!(unlock_vault_with(&f.db, &f.state, PASSWORD).is_err());
        unlock_vault_with(&f.db, &f.state, "nova-senha-789").unwrap();
        assert!(password_check_stored(&f.db).is_some());
    }

    #[test]
    fn legado_com_entradas_sem_verificador_nao_pode_ser_reinicializado() {
        let f = initialized_fixture();
        add(&f, "github.com", "ana", "senha-gh-1");
        lock_vault_with(&f.state).unwrap();
        remove_password_check(&f.db);

        assert!(initialize_vault_with(&f.db, &f.state, "nova-senha-789").is_err());

        unlock_vault_with(&f.db, &f.state, PASSWORD).unwrap();
        let entry = first_entry(&f);
        assert_eq!(password_of(&f, &entry.id), "senha-gh-1");
    }

    #[test]
    fn get_password_retorna_a_senha_da_entrada() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha-site");
        let entry = first_entry(&f);

        assert_eq!(password_of(&f, &entry.id), "senha-site");
    }

    #[test]
    fn get_password_entrada_inexistente_falha() {
        let f = initialized_fixture();

        assert!(matches!(
            get_password_with(&f.db, &f.state, "nao-existe"),
            Err(AppError::EntryNotFound)
        ));
    }

    #[test]
    fn get_password_com_cofre_bloqueado_falha() {
        let f = initialized_fixture();
        add(&f, "site.com", "ana", "senha");
        let entry = first_entry(&f);
        lock_vault_with(&f.state).unwrap();

        assert!(get_password_with(&f.db, &f.state, &entry.id).is_err());
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
        assert_eq!(password_of(&f, &after.id), "senha-nova");
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
        assert_eq!(password_of(&f, &entry.id), "senha");
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
