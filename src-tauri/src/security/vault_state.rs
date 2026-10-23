use std::sync::Mutex;
use crate::security::memory::SecureKey;

/// Estado gerenciado pelo Tauri para a sessão do cofre.
///
/// `None`  = cofre travado (não inicializado ou sessão encerrada)
/// `Some`  = cofre desbloqueado, chave mestra ativa em memória
///
/// Envolvido em `Mutex` para permitir mutação segura entre chamadas de comandos.
/// O Tauri gerencia o `Arc` externo via `.manage()`.
pub struct VaultState {
    pub master_key: Mutex<Option<SecureKey>>,
}

impl VaultState {
    pub fn new() -> Self {
        Self {
            master_key: Mutex::new(None),
        }
    }

    /// Retorna `true` se há uma chave mestra ativa (cofre desbloqueado).
    pub fn is_unlocked(&self) -> bool {
        self.master_key
            .lock()
            .expect("VaultState mutex envenenado")
            .is_some()
    }
}
