use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultEntry {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub password: String, // Essa string será encriptada antes de salvar
    pub created_at: DateTime<Utc>,
}

impl VaultEntry {
    // Construtor auxiliar
    pub fn new(domain: String, username: String, password: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            domain,
            username,
            password,
            created_at: Utc::now(),
        }
    }
}