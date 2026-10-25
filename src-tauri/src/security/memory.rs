use zeroize::Zeroize;

/// Contêiner seguro para a chave mestra AES-256 em memória.
///
/// Garante que os 32 bytes da chave são sobrescritos com zeros automaticamente
/// quando o valor sai de escopo (Drop). Não implementa Clone, Copy nem Debug
/// para evitar duplicação acidental ou vazamento da chave em logs.
pub struct SecureKey {
    inner: [u8; 32],
}

impl SecureKey {
    /// Envolve bytes de chave brutos em um contêiner com zeroização automática.
    /// O chamador não deve manter cópia dos bytes após esta chamada.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { inner: bytes }
    }

    /// Empresta os bytes da chave para operações criptográficas.
    /// Mantenha o empréstimo com o menor tempo de vida possível.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// Explicitamente NÃO implementado:
//   Clone  — duplicaria material de chave na memória
//   Copy   — mesmo problema
//   Debug  — imprimiria a chave em saídas de debug/log

#[cfg(test)]
mod tests {
    use super::SecureKey;

    #[test]
    fn secure_key_expoe_a_chave_por_emprestimo() {
        let bytes = [0xA5; 32];
        let key = SecureKey::new(bytes);

        assert_eq!(key.bytes(), &bytes);
    }
}
