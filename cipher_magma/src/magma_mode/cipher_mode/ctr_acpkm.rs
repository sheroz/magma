//! Implements Counter Encryption (CTR_ACPKM) mode

use crate::{MagmaMode, CipherOperation, CipherMode};
use crate::magma_core::constants::*;

/// Returns encrypted result as `Vec<u8>`
/// 
/// Implements buffer encrypting in Counter Encryption (CTR_ACPKM) mode
/// 
/// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
/// 
/// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
pub fn encrypt(magma_stream: &mut MagmaMode, buf: &[u8]) -> Vec<u8> {
    magma_stream.update_context(&CipherOperation::Encrypt, &CipherMode::CTR_ACPKM);

    cipher_ctr_acpkm(magma_stream, buf)
}

/// Returns decrypted result as `Vec<u8>`
/// 
/// Implements buffer decrypting in Counter Encryption (CTR_ACPKM) mode
/// 
/// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
/// 
/// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
pub fn decrypt(magma_stream: &mut MagmaMode, buf: &[u8]) -> Vec<u8> {
    magma_stream.update_context(&CipherOperation::Decrypt, &CipherMode::CTR_ACPKM);

    cipher_ctr_acpkm(magma_stream, buf)
}

/// Returns encrypted/decrypted as `Vec<u8>`
/// 
/// Implements the core of Counter Encryption (CTR_ACPKM) mode
/// 
/// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
/// 
/// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
fn cipher_ctr_acpkm(magma_stream: &mut MagmaMode, buf: &[u8]) -> Vec<u8> {

    let iv_ctr = magma_stream.prepare_vector_ctr();
    let mut result = Vec::<u8>::with_capacity(buf.len());

    let original_key = magma_stream.magma.key;
    let mut section_bits_processed = 0;

    let mut counter = match magma_stream.context.feedback.block {
        Some(block) => block,
        None => 0
    };

    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);

        let ctr = iv_ctr.wrapping_add(counter);
        counter += 1;

        let gamma = magma_stream.magma.encrypt(ctr);
        let output = gamma ^ block;

        result.extend_from_slice(&output.to_be_bytes()[..chunk.len()]);

        section_bits_processed += 64;
        if section_bits_processed >= CTR_ACPKM_SECTION_SIZE_N {
            let state = magma_stream.context.clone();
            magma_stream.set_mode(CipherMode::ECB);
            let section_key = magma_stream.encrypt(&CTR_ACPKM_D);
            magma_stream.magma.set_key_u8(&section_key);
            magma_stream.context = state;
            section_bits_processed = 0;
        }
    }

    // update the feedback state
    magma_stream.context.feedback.block = Some(counter);

    // restore the original cipher key
    magma_stream.magma.set_key_u32(&original_key);

    result
}

#[cfg(test)] 
mod tests {

    use super::*;

    #[test]
    fn encrypt_ctr_acpkm_r_1323565_1_017_2018() {
        // Test Vectors CTR-ACPKM
        // Р 1323565.1.017—2018
        // https://standartgost.ru/g/%D0%A0_1323565.1.017-2018
        // Page 11

        use crypto_vectors::gost::r1323565_1_017_2018::ctr_acpkm;

        let mut magma_stream = MagmaMode::with_key(ctr_acpkm::CIPHER_KEY.clone());

        let encrypted = encrypt(&mut magma_stream, &ctr_acpkm::PLAINTEXT);
        assert!(!encrypted.is_empty());

        assert_eq!(encrypted, ctr_acpkm::CIPHERTEXT);
    }

    #[test]
    fn decrypt_ctr_acpkm_r_1323565_1_017_2018() {
        // Test Vectors CTR-ACPKM
        // Р 1323565.1.017—2018
        // https://standartgost.ru/g/%D0%A0_1323565.1.017-2018
        // Page 11
        
        use crypto_vectors::gost::r1323565_1_017_2018::ctr_acpkm;

        let mut magma_stream = MagmaMode::with_key(ctr_acpkm::CIPHER_KEY.clone());
        let decrypted = decrypt(&mut magma_stream, &ctr_acpkm::CIPHERTEXT);
        assert_eq!(decrypted, ctr_acpkm::PLAINTEXT);
    }
}