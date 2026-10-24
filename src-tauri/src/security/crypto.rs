use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use std::error::Error;

// ── Constantes Argon2id (parâmetros OWASP 2023 para login interativo) ────────
// Memória: 64 MiB | Iterações: 3 | Paralelismo: 4
// Resistente a ataques GPU e ASIC (memory-hard).
const ARGON2_MEM_KIB: u32 = 65_536; // 64 MiB em KiB
const ARGON2_ITERS: u32 = 3;
const ARGON2_PARALLEL: u32 = 4;

/// Tamanho do salt Argon2 em bytes (128 bits — mínimo NIST SP 800-132).
pub const ARGON2_SALT_LEN: usize = 16;

// ── Geração de salt ──────────────────────────────────────────────────────────

/// Gera um salt Argon2 aleatório e criptograficamente seguro.
///
/// Deve ser chamado UMA ÚNICA VEZ na inicialização do cofre.
/// O resultado deve ser persistido em `vault_config` no banco.
pub fn generate_salt() -> [u8; ARGON2_SALT_LEN] {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

// ── Derivação de chave (KDF) ─────────────────────────────────────────────────

/// Deriva uma chave AES-256 de 32 bytes a partir da senha mestra via Argon2id.
///
/// # Argumentos
/// * `password` — Senha mestra em UTF-8, nunca armazenada em disco.
/// * `salt`     — Salt aleatório de 16 bytes lido do banco (`vault_config`).
///
/// # Retorno
/// 32 bytes aptos para uso com AES-256-GCM.
/// O chamador é responsável por zeroizar esses bytes ao terminar
/// (use `SecureKey` para garantia automática).
pub fn derive_key_from_password(
    password: &str,
    salt: &[u8; ARGON2_SALT_LEN],
) -> Result<[u8; 32], Box<dyn Error>> {
    let params = Params::new(ARGON2_MEM_KIB, ARGON2_ITERS, ARGON2_PARALLEL, Some(32))
        .map_err(|e| format!("Argon2 — parâmetros inválidos: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 — KDF falhou: {e}"))?;

    Ok(key)
}

// ── Encriptação ──────────────────────────────────────────────────────────────

/// Encripta `data` com AES-256-GCM usando `key`.
///
/// Retorna `(ciphertext, nonce)` — **ambos** devem ser armazenados.
/// O nonce é gerado aleatoriamente a cada chamada (12 bytes via OsRng).
///
/// # Nota de segurança
/// Cada campo encriptado com a mesma chave DEVE usar seu PRÓPRIO nonce.
/// Nunca compartilhe um nonce entre duas chamadas de encrypt() com a mesma chave.
pub fn encrypt(data: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|_| "AES-GCM — falha na encriptação")?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

// ── Decriptação ──────────────────────────────────────────────────────────────

/// Decripta ciphertext AES-256-GCM.
///
/// Retorna `Err` em caso de chave errada, dados corrompidos ou plaintext não-UTF-8.
/// A tag de autenticação GCM é verificada automaticamente pela crate `aes-gcm`.
pub fn decrypt(
    ciphertext: &[u8],
    nonce: &[u8],
    key: &[u8; 32],
) -> Result<String, Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "AES-GCM — falha na decriptação (chave errada ou dados corrompidos)")?;

    Ok(String::from_utf8(plaintext)?)
}

// ── Verificador de senha mestra ──────────────────────────────────────────────

/// Texto conhecido cifrado na inicialização para validar a senha no desbloqueio.
const PASSWORD_CHECK_PLAINTEXT: &str = "secure-vault:password-check";
const NONCE_LEN: usize = 12;

/// Gera o verificador: `nonce (12 bytes) || ciphertext`, cifrado com `key`.
pub fn make_password_check(key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let (ciphertext, nonce) = encrypt(PASSWORD_CHECK_PLAINTEXT, key)?;
    let mut blob = nonce;
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Retorna `true` somente se `blob` foi gerado com a mesma `key`.
pub fn verify_password_check(blob: &[u8], key: &[u8; 32]) -> bool {
    if blob.len() <= NONCE_LEN {
        return false;
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    matches!(
        decrypt(ciphertext, nonce, key),
        Ok(plaintext) if plaintext == PASSWORD_CHECK_PLAINTEXT
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const KEY: [u8; 32] = [7u8; 32];
    const OTHER_KEY: [u8; 32] = [9u8; 32];

    #[test]
    fn round_trip_recupera_o_texto_original() {
        for text in ["", "senha123", "açúcar 🔐 日本語"] {
            let (ciphertext, nonce) = encrypt(text, &KEY).unwrap();
            assert_eq!(decrypt(&ciphertext, &nonce, &KEY).unwrap(), text);
        }
    }

    #[test]
    fn chave_errada_falha() {
        let (ciphertext, nonce) = encrypt("segredo", &KEY).unwrap();
        assert!(decrypt(&ciphertext, &nonce, &OTHER_KEY).is_err());
    }

    #[test]
    fn ciphertext_adulterado_falha() {
        let (mut ciphertext, nonce) = encrypt("segredo", &KEY).unwrap();
        ciphertext[0] ^= 0x01;
        assert!(decrypt(&ciphertext, &nonce, &KEY).is_err());
    }

    #[test]
    fn nonces_e_ciphertexts_distintos_a_cada_cifragem() {
        let mut nonces = HashSet::new();
        let mut ciphertexts = HashSet::new();
        for _ in 0..100 {
            let (ciphertext, nonce) = encrypt("mesmo texto", &KEY).unwrap();
            assert_eq!(nonce.len(), NONCE_LEN);
            nonces.insert(nonce);
            ciphertexts.insert(ciphertext);
        }
        assert_eq!(nonces.len(), 100);
        assert_eq!(ciphertexts.len(), 100);
    }

    #[test]
    fn verificador_aceita_chave_correta_e_rejeita_errada() {
        let blob = make_password_check(&KEY).unwrap();
        assert!(verify_password_check(&blob, &KEY));
        assert!(!verify_password_check(&blob, &OTHER_KEY));
    }

    #[test]
    fn verificador_rejeita_blob_vazio_ou_truncado() {
        let blob = make_password_check(&KEY).unwrap();
        assert!(!verify_password_check(&[], &KEY));
        assert!(!verify_password_check(&blob[..NONCE_LEN], &KEY));
    }

    #[test]
    fn kdf_e_deterministica_e_sensivel_ao_salt() {
        let salt = [1u8; ARGON2_SALT_LEN];
        let other_salt = [2u8; ARGON2_SALT_LEN];
        let k1 = derive_key_from_password("senha-mestra", &salt).unwrap();
        let k2 = derive_key_from_password("senha-mestra", &salt).unwrap();
        let k3 = derive_key_from_password("senha-mestra", &other_salt).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }
}
