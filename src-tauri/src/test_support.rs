// Utilitários compartilhados pelos testes. Só é compilado com `cargo test`.

use std::path::PathBuf;
use uuid::Uuid;

use crate::infrastructure::database::Database;

/// Diretório temporário único, removido ao sair de escopo.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("secure-vault-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("não foi possível criar diretório temporário");
        Self { path }
    }

    pub fn database(&self) -> Database {
        Database::new(self.path.join("securevault.db"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
