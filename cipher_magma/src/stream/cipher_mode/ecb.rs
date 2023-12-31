//! Implements Electronic Codebook (ECB) mode

use crate::{Magma, MagmaStream, CipherOperation, CipherMode};

/// Returns encrypted result as `Vec<u8>`
/// 
/// Implements buffer encrypting in Electronic Codebook (ECB) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 13, Section 5.1.1
pub fn encrypt(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {
    magma.update_context(CipherOperation::Encrypt, CipherMode::ECB);

    let m_invoke = Magma::encrypt;
    cipher_ecb(magma, buf, m_invoke)
}

/// Returns decrypted result as `Vec<u8>`
/// 
/// Implements buffer decrypting in Electronic Codebook (ECB) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 13, Section 5.1.2
pub fn decrypt(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {
    magma.update_context(CipherOperation::Decrypt, CipherMode::ECB);

    let m_invoke = Magma::decrypt;
    cipher_ecb(magma, buf, m_invoke)
}

/// Returns encrypted/decrypted result as `Vec<u8>`
/// 
/// Implements the core of Electronic Codebook (ECB) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 13, Section 5.1
fn cipher_ecb(magma: &MagmaStream, buf: &[u8], m_invoke: fn(&Magma, u64) -> u64) -> Vec<u8> {
    let mut result = Vec::<u8>::with_capacity(buf.len());
    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);
        let output = m_invoke(&magma.core, block);
        result.extend_from_slice(&output.to_be_bytes());
    }
    result
}

#[cfg(test)] 
mod tests {

    use super::*;

    #[test]
    fn encrypt_ecb_gost_r_34_13_2015() {

        use crypto_vectors::gost::r3413_2015;

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::ECB);
        let encrypted = encrypt(&mut magma, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_ECB.to_be_bytes());
        assert_eq!(encrypted, expected);
    }
    
    #[test]
    fn decrypt_ecb_gost_r_34_13_2015() {
        use crypto_vectors::gost::r3413_2015;

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::ECB);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT1_ECB.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT2_ECB.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT3_ECB.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT4_ECB.to_be_bytes());

        let decrypted = decrypt(&mut magma, &encrypted);
        assert_eq!(decrypted, source);
    }    
}