use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce // Or `XChaCha20Poly1305` which is also great
};
use rand::{rngs::OsRng, RngCore};
use std::error::Error;

// Gera uma chave aleatória (para criar bancos novos)
// Na prática real, isso viria do Argon2 derivado da senha mestra
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn encrypt(data: &str, key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key.into());
    
    // Nonce (Number used ONCE) deve ser único para cada registro
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|_| "Falha na encriptação")?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt(encrypted_data: &[u8], nonce_data: &[u8], key: &[u8; 32]) -> Result<String, Box<dyn Error>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce_data);

    let plaintext = cipher.decrypt(nonce, encrypted_data)
        .map_err(|_| "Falha na desencriptação (Senha errada ou dados corrompidos)")?;

    Ok(String::from_utf8(plaintext)?)
}