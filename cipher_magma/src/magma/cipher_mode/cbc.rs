//! Implements Cipher Block Chaining (CBC) mode

use std::collections::VecDeque;

use crate::{magma::Magma, CipherOperation, CipherMode};

/// Returns encrypted result as `Vec<u8>`
/// 
/// Implements buffer encrypting in Cipher Block Chaining (CBC) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 20, Section 5.4.1
pub fn encrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {

    core.ensure_iv_not_empty();

    core.update_context(&CipherOperation::Encrypt, &CipherMode::CBC);
    let mut register_r = match &core.context.feedback.vector {
        Some(vector) => vector.clone(),
        None => VecDeque::from(core.iv.clone())
    };

    let mut result = Vec::<u8>::with_capacity(buf.len());

    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);

        let register_n= register_r.pop_front().unwrap();
        let output = core.encrypt(block ^ register_n);

        register_r.push_back(output);

        result.extend_from_slice(&output.to_be_bytes());
    }

    // update the feedback state
    core.context.feedback.vector = Some(register_r);

    result
}

/// Returns decrypted result as `Vec<u8>`
/// 
/// Implements buffer decrypting in Cipher Block Chaining (CBC) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 21, Section 5.4.2
pub fn decrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {

    core.ensure_iv_not_empty();

    core.update_context(&CipherOperation::Decrypt, &CipherMode::CBC);
    let mut register_r = match &core.context.feedback.vector {
        Some(vector) => vector.clone(),
        None => VecDeque::from(core.iv.clone())
    };

    let mut result = Vec::<u8>::with_capacity(buf.len());

    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);

        let register_n= register_r.pop_front().unwrap();
        let output = core.decrypt(block) ^ register_n;
        
        register_r.push_back(block);

        result.extend_from_slice(&output.to_be_bytes());
    }

    // update the feedback state
    core.context.feedback.vector = Some(register_r);

    result
}

#[cfg(test)] 
mod tests {

    use super::*;

    #[test]
    fn cbc_steps_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4

        // m = 3n = 192
        // IV = 1234567890abcdef234567890abcdef134567890abcdef12

        use crypto_vectors::gost::r3413_2015;

        let magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);

        let iv =  Magma::IV_GOST_R3413_2015;
        let mut r = [iv[0], iv[1], iv[2]];

        let p1 = r3413_2015::PLAINTEXT1;
        let i1 = p1 ^ r[0];
        assert_eq!(i1, 0x80eaa613acb8c7b6_u64); 
        let o1 = magma.encrypt(i1);
        assert_eq!(o1, 0x96d1b05eea683919_u64); 
        let c1 = o1;
        assert_eq!(c1, r3413_2015::CIPHERTEXT1_CBC); 
        r[0] = r[1];
        r[1] = r[2];
        r[2] = o1;
        
        let p2 = r3413_2015::PLAINTEXT2;
        let i2 = p2 ^ r[0];
        assert_eq!(i2, 0xf811a08df2a443d1_u64); 
        let o2 = magma.encrypt(i2);
        assert_eq!(o2, 0xaff76129abb937b9_u64); 
        let c2 = o2;
        assert_eq!(c2, r3413_2015::CIPHERTEXT2_CBC); 
        r[0] = r[1];
        r[1] = r[2];
        r[2] = o2;

        let p3 = r3413_2015::PLAINTEXT3;
        let i3 = p3 ^ r[0];
        assert_eq!(i3, 0x7ece83becc65ed5e_u64); 
        let o3 = magma.encrypt(i3);
        assert_eq!(o3, 0x5058b4a1c4bc0019_u64); 
        let c3 = o3;
        assert_eq!(c3, r3413_2015::CIPHERTEXT3_CBC); 
        r[0] = r[1];
        r[1] = r[2];
        r[2] = o3;

        let p4 = r3413_2015::PLAINTEXT4;
        let i4 = p4 ^ r[0];
        assert_eq!(i4, 0x1fc3f0c5fddd4758_u64); 
        let o4 = magma.encrypt(i4);
        assert_eq!(o4, 0x20b78b1a7cd7e667_u64); 
        let c4 = o4;
        assert_eq!(c4, r3413_2015::CIPHERTEXT4_CBC); 
    }

    #[test]
    fn encrypt_cbc_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4

        use crypto_vectors::gost::r3413_2015;

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);
        let encrypted = encrypt(&mut magma, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CBC.to_be_bytes());
        assert_eq!(encrypted, expected);
    }

    #[test]
    fn decrypt_cbc_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4

        use crypto_vectors::gost::r3413_2015;

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT1_CBC.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT2_CBC.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT3_CBC.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT4_CBC.to_be_bytes());

        let decrypted = decrypt(&mut magma, &encrypted);
        assert_eq!(decrypted, source);
    }
}
