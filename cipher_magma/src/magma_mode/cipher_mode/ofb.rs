//! Implements Output Feedback (OFB) mode

use std::collections::VecDeque;
use crate::{MagmaMode, CipherOperation, CipherMode};

/// Returns encrypted result as `Vec<u8>`
/// 
/// Implements buffer encrypting in Output Feedback (OFB) Mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 16, Section 5.3
pub fn encrypt(magma_stream: &mut MagmaMode, buf: &[u8]) -> Vec<u8> {
    magma_stream.update_context(&CipherOperation::Encrypt, &CipherMode::OFB);
    cipher_ofb(magma_stream, buf)
}

/// Returns decrypted result as `Vec<u8>`
/// 
/// Implements buffer decrypting in Output Feedback (OFB) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 16, Section 5.3
pub fn decrypt(magma_stream: &mut MagmaMode, buf: &[u8]) -> Vec<u8> {
    magma_stream.update_context(&CipherOperation::Decrypt, &CipherMode::OFB);
    cipher_ofb(magma_stream, buf)
}

/// Returns encrypted/decrypted result as `Vec<u8>`
/// 
/// Implements the core of Output Feedback (OFB) mode
/// 
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// Page 16, Section 5.3
fn cipher_ofb(magma_stream: &mut MagmaMode, buf: &[u8]) -> Vec<u8> {

    magma_stream.ensure_iv_not_empty();

    let mut register_r = match &magma_stream.context.feedback.vector {
        Some(vector) => vector.clone(),
        None => VecDeque::from(magma_stream.context.iv.clone())
    };

    let mut result = Vec::<u8>::with_capacity(buf.len());

    for chunk in buf.chunks(8) {
        let mut array_u8 = [0u8;8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
        let block = u64::from_be_bytes(array_u8);

        let register_n= register_r.pop_front().unwrap();
        let ofb = magma_stream.magma.encrypt(register_n);
        let output = ofb ^ block;

        register_r.push_back(ofb);

        result.extend_from_slice(&output.to_be_bytes()[..chunk.len()]);
    }

    // update the feedback state
    magma_stream.context.feedback.vector = Some(register_r);

    result
}

#[cfg(test)] 
mod tests {

    use super::*;
    use crypto_vectors::gost::r3413_2015;
    use crate::magma_core::constants::*;

    #[test]
    fn ofb_steps_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 37, Section A.2.3

        // s = n = 64, m = 2n = 128
        // IV = 1234567890abcdef234567890abcdef1
        let iv = 0x1234567890abcdef234567890abcdef1_u128;
        
        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        let mut r = [IV_GOST_R3413_2015[0], IV_GOST_R3413_2015[1]];
        let mut v1 = Vec::from(r[0].to_be_bytes());
        v1.extend_from_slice(&r[1].to_be_bytes());
        assert_eq!(iv.to_be_bytes(), v1.as_slice());

        use crate::Magma;
        let magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());

        let p1 = r3413_2015::PLAINTEXT1;
        let i1 = r[0];
        assert_eq!(i1, 0x1234567890abcdef_u64); 
        let o1 = magma.encrypt(i1);
        assert_eq!(o1, 0x49e910895a8336da_u64); 
        let c1 = p1 ^ o1;
        assert_eq!(c1, r3413_2015::CIPHERTEXT1_OFB);

        r[0] = r[1];
        r[1] = o1;

        let p2 = r3413_2015::PLAINTEXT2;
        let i2 = r[0];
        assert_eq!(i2, 0x234567890abcdef1_u64); 
        let o2 = magma.encrypt(i2);
        assert_eq!(o2, 0xd612a348e78295bc_u64); 
        let c2 = p2 ^ o2;
        assert_eq!(c2, r3413_2015::CIPHERTEXT2_OFB);

        r[0] = r[1];
        r[1] = o2;

        let p3 = r3413_2015::PLAINTEXT3;
        let i3 = r[0];
        assert_eq!(i3, 0x49e910895a8336da_u64); 
        let o3 = magma.encrypt(i3);
        assert_eq!(o3, 0xea60cb4c24a63032_u64); 
        let c3 = p3 ^ o3;
        assert_eq!(c3, r3413_2015::CIPHERTEXT3_OFB);

        r[0] = r[1];
        r[1] = o3;

        let p4 = r3413_2015::PLAINTEXT4;
        let i4 = r[0];
        assert_eq!(i4, 0xd612a348e78295bc_u64); 
        let o4 = magma.encrypt(i4);
        assert_eq!(o4, 0x4136af23aafaa544_u64); 
        let c4 = p4 ^ o4;
        assert_eq!(c4, r3413_2015::CIPHERTEXT4_OFB);
    }

    #[test]
    fn encrypt_ofb_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 37, Section A.2.3

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma_stream = MagmaMode::with_key(r3413_2015::CIPHER_KEY.clone());

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        magma_stream.set_iv(&IV_GOST_R3413_2015[..2]);

        let encrypted = encrypt(&mut magma_stream, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_OFB.to_be_bytes());
        assert_eq!(encrypted, expected);
    }

    #[test]
    fn decrypt_ofb_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 37, Section A.2.3

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma_stream = MagmaMode::with_key(r3413_2015::CIPHER_KEY.clone());

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        magma_stream.set_iv(&IV_GOST_R3413_2015[..2]);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT1_OFB.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT2_OFB.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT3_OFB.to_be_bytes());
        encrypted.extend_from_slice(&r3413_2015::CIPHERTEXT4_OFB.to_be_bytes());

        let decrypted = decrypt(&mut magma_stream, &encrypted);
        assert_eq!(decrypted, source);
    }
}
