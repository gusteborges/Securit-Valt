use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub password: String, // Essa string será encriptada antes de salvar
    pub created_at: DateTime<Utc>,
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
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

#[cfg(test)]
mod tests {
    use super::VaultEntry;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn novo_modelo_tem_id_uuid_campos_e_data_atuais() {
        let before = Utc::now();
        let entry = VaultEntry::new("example.com".into(), "ana".into(), "senha-segura".into());
        let after = Utc::now();

        assert!(Uuid::parse_str(&entry.id).is_ok());
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.username, "ana");
        assert_eq!(entry.password, "senha-segura");
        assert!(entry.created_at >= before && entry.created_at <= after);
    }

    #[test]
    fn novos_modelos_recebem_ids_distintos() {
        let first = VaultEntry::new("a.com".into(), "ana".into(), "one".into());
        let second = VaultEntry::new("b.com".into(), "bia".into(), "two".into());

        assert_ne!(first.id, second.id);
    }
}
