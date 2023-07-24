use crate::Magma;
use crate::core::CipherBuffer;
use crate::CipherOperation;
use crate::CipherMode;

#[allow(non_camel_case_types)]
pub struct CTR_ACPKM;

impl CipherBuffer for CTR_ACPKM {
    /// Returns encrypted result as `Vec<u8>`
    /// 
    /// Implements buffer encrypting in Counter Encryption (CTR_ACPKM) Mode
    /// 
    /// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
    /// 
    /// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
    fn encrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {
        CTR_ACPKM::cipher_ctr_acpkm(core, buf)
    }

    /// Returns decrypted result as `Vec<u8>`
    /// 
    /// Implements buffer decrypting in Counter Encryption (CTR_ACPKM) Mode
    /// 
    /// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
    /// 
    /// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
    fn decrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {
        CTR_ACPKM::cipher_ctr_acpkm(core, buf)
    }
}

impl CTR_ACPKM {
    /// Returns encrypted/decrypted as `Vec<u8>`
    /// 
    /// Implements Counter Encryption (CTR_ACPKM) Mode
    /// 
    /// [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html#section-6.2.2)
    /// 
    /// [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
    fn cipher_ctr_acpkm(core: &mut Magma, buf: &[u8]) -> Vec<u8> {

        let iv_ctr = core.prepare_vector_ctr();
        let mut result = Vec::<u8>::with_capacity(buf.len());

        let original_key = core.cipher_key;
        let mut section_bits_processed = 0;

        for (chunk_index, chunk) in buf.chunks(8).enumerate() {
            let mut array_u8 = [0u8;8];
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            let block = u64::from_be_bytes(array_u8);

            let ctr = iv_ctr.wrapping_add(chunk_index as u64);

            let gamma = core.encrypt(ctr);
            let output = gamma ^ block;

            result.extend_from_slice(&output.to_be_bytes()[..chunk.len()]);

            section_bits_processed += 64;
            if section_bits_processed >= Magma::CTR_ACPKM_SECTION_SIZE_N {
                let section_key = core.cipher(&Magma::CTR_ACPKM_D, &CipherOperation::Encrypt, &CipherMode::ECB);
                core.set_key_from_bytes(&section_key);
                section_bits_processed = 0;
            }
        }

        // restore the original cipher key
        core.set_key(&original_key);

        result
    }
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

        let mut magma = Magma::new();
        magma.set_key_from_bytes(&ctr_acpkm::CIPHER_KEY);

        let encrypted = CTR_ACPKM::encrypt(&mut magma, &ctr_acpkm::PLAINTEXT);
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

        let mut magma = Magma::new();
        magma.set_key_from_bytes(&ctr_acpkm::CIPHER_KEY);
        let decrypted = CTR_ACPKM::decrypt(&mut magma, &ctr_acpkm::CIPHERTEXT);
        assert_eq!(decrypted, ctr_acpkm::PLAINTEXT);
    }
}