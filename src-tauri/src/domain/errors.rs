use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Validation(String),
    VaultLocked,
    VaultNotInitialized,
    VaultAlreadyInitialized,
    IncorrectMasterPassword,
    EntryNotFound,
    Database(rusqlite::Error),
    Persistence(String),
    Crypto(String),
    Io(std::io::Error),
    Platform(String),
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message)
            | Self::Crypto(message)
            | Self::Platform(message)
            | Self::Persistence(message)
            | Self::Internal(message) => f.write_str(message),
            Self::VaultLocked => {
                f.write_str("Cofre bloqueado. Desbloqueie o cofre antes de continuar.")
            }
            Self::VaultNotInitialized => {
                f.write_str("Cofre não inicializado. Execute initialize_vault primeiro.")
            }
            Self::VaultAlreadyInitialized => {
                f.write_str("Cofre já inicializado. Use unlock_vault para desbloquear.")
            }
            Self::IncorrectMasterPassword => f.write_str("Senha mestra incorreta."),
            Self::EntryNotFound => f.write_str("Entrada não encontrada."),
            Self::Database(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;

    #[test]
    fn erros_de_fluxo_exibem_mensagens_estaveis_para_o_ipc() {
        assert_eq!(
            AppError::VaultLocked.to_string(),
            "Cofre bloqueado. Desbloqueie o cofre antes de continuar."
        );
        assert_eq!(
            AppError::IncorrectMasterPassword.to_string(),
            "Senha mestra incorreta."
        );
        assert_eq!(
            AppError::EntryNotFound.to_string(),
            "Entrada não encontrada."
        );
    }

    #[test]
    fn erros_contextuais_preservam_a_mensagem() {
        assert_eq!(
            AppError::Validation("campo obrigatório".into()).to_string(),
            "campo obrigatório"
        );
        assert_eq!(
            AppError::Persistence("falha ao salvar".into()).to_string(),
            "falha ao salvar"
        );
    }
}
