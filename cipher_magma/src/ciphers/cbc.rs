use std::collections::VecDeque;

use crate::Magma;
use crate::core::CipherBuffer;

pub struct CBC;

impl CipherBuffer for CBC {
    /// Returns encrypted result as `Vec<u8>`
    /// 
    /// Implements buffer encrypting in Cipher Block Chaining (CBC) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 20, Section 5.4.1
    fn encrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {

        core.ensure_iv_not_empty();
        let mut register_r = VecDeque::from(core.iv.clone());

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

        result
    }

    /// Returns decrypted result as `Vec<u8>`
    /// 
    /// Implements buffer decrypting in Cipher Block Chaining (CBC) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 21, Section 5.4.2
    fn decrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {

        core.ensure_iv_not_empty();
        let mut register_r = VecDeque::from(core.iv.clone());

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

        result
    }
}

#[cfg(test)] 
mod tests {

    use super::*;

    const CIPHER_KEY_RFC8891: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];

    const PLAINTEXT1_GOST_R3413_2015: u64 = 0x92def06b3c130a59_u64;
    const PLAINTEXT2_GOST_R3413_2015: u64 = 0xdb54c704f8189d20_u64;
    const PLAINTEXT3_GOST_R3413_2015: u64 = 0x4a98fb2e67a8024c_u64;
    const PLAINTEXT4_GOST_R3413_2015: u64 = 0x8912409b17b57e41_u64;

    // Test vectors GOST R 34.13-2015
    // Encrypting in CBC Mode
    // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
    // Page 38, Section A.2.4
    const ENCRYPTED1_CBC_GOST_R3413_2015: u64 = 0x96d1b05eea683919_u64;
    const ENCRYPTED2_CBC_GOST_R3413_2015: u64 = 0xaff76129abb937b9_u64;
    const ENCRYPTED3_CBC_GOST_R3413_2015: u64 = 0x5058b4a1c4bc0019_u64;
    const ENCRYPTED4_CBC_GOST_R3413_2015: u64 = 0x20b78b1a7cd7e667_u64;

    #[test]
    fn cbc_steps_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4

        // m = 3n = 192
        // IV = 1234567890abcdef234567890abcdef134567890abcdef12

        let magma = Magma::with_key(&CIPHER_KEY_RFC8891);

        let iv =  Magma::IV_GOST_R3413_2015;
        let mut r = [iv[0], iv[1], iv[2]];

        let p1 = PLAINTEXT1_GOST_R3413_2015;
        let i1 = p1 ^ r[0];
        assert_eq!(i1, 0x80eaa613acb8c7b6_u64); 
        let o1 = magma.encrypt(i1);
        assert_eq!(o1, 0x96d1b05eea683919_u64); 
        let c1 = o1;
        assert_eq!(c1, ENCRYPTED1_CBC_GOST_R3413_2015); 
        r[0] = r[1];
        r[1] = r[2];
        r[2] = o1;
        
        let p2 = PLAINTEXT2_GOST_R3413_2015;
        let i2 = p2 ^ r[0];
        assert_eq!(i2, 0xf811a08df2a443d1_u64); 
        let o2 = magma.encrypt(i2);
        assert_eq!(o2, 0xaff76129abb937b9_u64); 
        let c2 = o2;
        assert_eq!(c2, ENCRYPTED2_CBC_GOST_R3413_2015); 
        r[0] = r[1];
        r[1] = r[2];
        r[2] = o2;

        let p3 = PLAINTEXT3_GOST_R3413_2015;
        let i3 = p3 ^ r[0];
        assert_eq!(i3, 0x7ece83becc65ed5e_u64); 
        let o3 = magma.encrypt(i3);
        assert_eq!(o3, 0x5058b4a1c4bc0019_u64); 
        let c3 = o3;
        assert_eq!(c3, ENCRYPTED3_CBC_GOST_R3413_2015); 
        r[0] = r[1];
        r[1] = r[2];
        r[2] = o3;

        let p4 = PLAINTEXT4_GOST_R3413_2015;
        let i4 = p4 ^ r[0];
        assert_eq!(i4, 0x1fc3f0c5fddd4758_u64); 
        let o4 = magma.encrypt(i4);
        assert_eq!(o4, 0x20b78b1a7cd7e667_u64); 
        let c4 = o4;
        assert_eq!(c4, ENCRYPTED4_CBC_GOST_R3413_2015); 
    }

    #[test]
    fn encrypt_cbc_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&PLAINTEXT1_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT2_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT3_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT4_GOST_R3413_2015.to_be_bytes());

        let mut magma = Magma::with_key(&CIPHER_KEY_RFC8891);
        let encrypted = CBC::encrypt(&mut magma, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&ENCRYPTED1_CBC_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED2_CBC_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED3_CBC_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED4_CBC_GOST_R3413_2015.to_be_bytes());
        assert_eq!(encrypted, expected);
    }

    #[test]
    fn decrypt_cbc_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&PLAINTEXT1_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT2_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT3_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT4_GOST_R3413_2015.to_be_bytes());

        let mut magma = Magma::with_key(&CIPHER_KEY_RFC8891);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&ENCRYPTED1_CBC_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED2_CBC_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED3_CBC_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED4_CBC_GOST_R3413_2015.to_be_bytes());

        let decrypted = CBC::decrypt(&mut magma, &encrypted);
        assert_eq!(decrypted, source);
    }
}
