//! Implements Counter Encryption (CTR_ACPKM) mode

use crate::{MagmaStream, CipherOperation, CipherMode};
use crate::core::constants::*;

/// Returns encrypted result as `Vec<u8>`
/// 
/// Implements buffer encrypting in Counter Encryption (CTR_ACPKM) mode
/// 
/// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
/// 
/// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
pub fn encrypt(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {
    magma.update_context(&CipherOperation::Encrypt, &CipherMode::CTR_ACPKM);

    cipher_ctr_acpkm(magma, buf)
}

/// Returns decrypted result as `Vec<u8>`
/// 
/// Implements buffer decrypting in Counter Encryption (CTR_ACPKM) mode
/// 
/// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
/// 
/// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
pub fn decrypt(magma_stream: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {
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
fn cipher_ctr_acpkm(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {

    let iv_ctr = magma.prepare_vector_ctr();
    let mut result = Vec::<u8>::with_capacity(buf.len());

    let original_key = magma.core.key;
    let mut section_bits_processed = 0;

    let mut counter = match magma.context.feedback.block {
        Some(block) => block,
        None => 0
    };

    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);

        let ctr = iv_ctr.wrapping_add(counter);
        counter += 1;

        let gamma = magma.core.encrypt(ctr);
        let output = gamma ^ block;

        result.extend_from_slice(&output.to_be_bytes()[..chunk.len()]);

        section_bits_processed += 64;
        if section_bits_processed >= CTR_ACPKM_SECTION_SIZE_N {
            let context = magma.context.clone();
            magma.set_mode(CipherMode::ECB);
            let section_key = magma.encrypt(&CTR_ACPKM_D);
            magma.core.set_key_u8(&section_key);
            magma.context = context;
            section_bits_processed = 0;
        }
    }

    // update the feedback state
    magma.context.feedback.block = Some(counter);

    // restore the original cipher key
    magma.core.set_key_u32(&original_key);

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

        let mut magma = MagmaStream::new(ctr_acpkm::CIPHER_KEY.clone(), CipherMode::CTR_ACPKM);

        let encrypted = encrypt(&mut magma, &ctr_acpkm::PLAINTEXT);
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

        let mut magma = MagmaStream::new(ctr_acpkm::CIPHER_KEY.clone(), CipherMode::CTR_ACPKM);

        let decrypted = decrypt(&mut magma, &ctr_acpkm::CIPHERTEXT);
        assert_eq!(decrypted, ctr_acpkm::PLAINTEXT);
    }
}