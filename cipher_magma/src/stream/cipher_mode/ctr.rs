//! Implements Counter Encryption (CTR) mode

use crate::{MagmaStream, CipherOperation, CipherMode};

/// Returns encrypted result as `Vec<u8>`
/// 
/// Implements buffer encrypting in Counter Encryption (CTR) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 15, Section 5.2.1
pub fn encrypt(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {
    magma.update_context(CipherOperation::Encrypt, CipherMode::CTR);
    cipher_ctr(magma, buf)
}

/// Returns decrypted result as `Vec<u8>`
/// 
/// Implements buffer decrypting in Counter Encryption (CTR) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 15, Section 5.2.2
pub fn decrypt(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {
    magma.update_context(CipherOperation::Decrypt, CipherMode::CTR);
    cipher_ctr(magma, buf)
}

/// Returns encrypted/decrypted result as `Vec<u8>`
/// 
/// Implements the core Counter Encryption (CTR) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 14, Section 5.2
fn cipher_ctr(magma: &mut MagmaStream, buf: &[u8]) -> Vec<u8> {

    let iv_ctr = magma.prepare_vector_ctr();
    let mut counter = match magma.context.feedback.block {
        Some(block) => block,
        None => 0
    };

    let mut result = Vec::<u8>::with_capacity(buf.len());

    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);

        let ctr = iv_ctr.wrapping_add(counter);
        counter += 1;

        let gamma = magma.core.encrypt(ctr);
        let output =  gamma ^ block;

        result.extend_from_slice(&output.to_be_bytes()[..chunk.len()]);
    }

    // update the feedback state
    magma.context.feedback.block = Some(counter);

    result
}

#[cfg(test)] 
mod tests {

    use super::*;
    use crypto_vectors::gost::r3413_2015;

    #[test]
    fn ctr_steps_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 36, Section A.2.2

        use crate::Magma;
        let magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());

        let iv = 0x12345678_u32;

        let iv_extended = (iv as u64 ) << 32;

        let mut pass_count = 0;
        let p1 = r3413_2015::PLAINTEXT1;
        let i1 = iv_extended.wrapping_add(pass_count);
        assert_eq!(i1, 0x1234567800000000_u64);
        let o1 = magma.encrypt(i1);
        assert_eq!(o1, 0xdc46e167aba4b365_u64);
        let c1 = p1 ^ o1;
        assert_eq!(c1, r3413_2015::CIPHERTEXT1_CTR);

        pass_count += 1;
        let p2 = r3413_2015::PLAINTEXT2;
        let i2 = iv_extended.wrapping_add(pass_count);
        assert_eq!(i2, 0x1234567800000001_u64);
        let o2 = magma.encrypt(i2);
        assert_eq!(o2, 0xe571ca972ef0c049_u64);
        let c2 = p2 ^ o2;
        assert_eq!(c2, r3413_2015::CIPHERTEXT2_CTR);

        pass_count += 1;
        let p3 = r3413_2015::PLAINTEXT3;
        let i3 = iv_extended.wrapping_add(pass_count);
        assert_eq!(i3, 0x1234567800000002_u64);
        let o3 = magma.encrypt(i3);
        assert_eq!(o3, 0x59f57da6601ad9a3_u64);
        let c3 = p3 ^ o3;
        assert_eq!(c3, r3413_2015::CIPHERTEXT3_CTR);

        pass_count += 1;
        let p4 = r3413_2015::PLAINTEXT4;
        let i4 = iv_extended.wrapping_add(pass_count);
        assert_eq!(i4, 0x1234567800000003_u64);
        let o4 = magma.encrypt(i4);
        assert_eq!(o4, 0xdf9cf61bbce7df6c_u64);
        let c4 = p4 ^ o4;
        assert_eq!(c4, r3413_2015::CIPHERTEXT4_CTR);
    }

    #[test]
    fn encrypt_ctr_gost_r_34_13_2015() {
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::CTR);
        let encrypted = encrypt(&mut magma, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CTR.to_be_bytes());
        assert_eq!(encrypted, expected);
    }
    
    #[test]
    fn decrypt_ctr_gost_r_34_13_2015() {
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::CTR);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT1_CTR.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT2_CTR.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT3_CTR.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT4_CTR.to_be_bytes());

        let decrypted = decrypt(&mut magma, &encrypted);
        assert_eq!(decrypted, source);
    }    
}