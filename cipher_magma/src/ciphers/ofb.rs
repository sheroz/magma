use std::collections::VecDeque;

use crate::Magma;
use crate::core::CipherBuffer;

pub struct OFB;

impl CipherBuffer for OFB {
    /// Returns encrypted result as `Vec<u8>`
    /// 
    /// Implements buffer encrypting in Output Feedback (OFB) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 16, Section 5.3
    fn encrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {
        OFB::cipher_ofb(core, buf)
    }

    /// Returns decrypted result as `Vec<u8>`
    /// 
    /// Implements buffer decrypting in Output Feedback (OFB) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 16, Section 5.3
    fn decrypt(core: &mut Magma, buf: &[u8]) -> Vec<u8> {
        OFB::cipher_ofb(core, buf)
    }
}

impl OFB {
    /// Returns encrypted/decrypted result as `Vec<u8>`
    /// 
    /// Implements Output Feedback (OFB) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 16, Section 5.3
    fn cipher_ofb(core: &Magma, buf: &[u8]) -> Vec<u8> {

        core.ensure_iv_not_empty();
        let mut register_r = VecDeque::from(core.iv.clone());

        let mut result = Vec::<u8>::with_capacity(buf.len());

        for chunk in buf.chunks(8) {
            let mut array_u8 = [0u8;8];
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            let block = u64::from_be_bytes(array_u8);

            let register_n= register_r.pop_front().unwrap();
            let ofb = core.encrypt(register_n);
            let output = ofb ^ block;

            register_r.push_back(ofb);

            result.extend_from_slice(&output.to_be_bytes()[..chunk.len()]);
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
    // Encrypting in OFB Mode
    // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
    // Page 37, Section A.2.3
    const ENCRYPTED1_OFB_GOST_R3413_2015: u64 = 0xdb37e0e266903c83_u64;
    const ENCRYPTED2_OFB_GOST_R3413_2015: u64 = 0x0d46644c1f9a089c_u64;
    const ENCRYPTED3_OFB_GOST_R3413_2015: u64 = 0xa0f83062430e327e_u64;        
    const ENCRYPTED4_OFB_GOST_R3413_2015: u64 = 0xc824efb8bd4fdb05_u64;

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
        let mut r = [Magma::IV_GOST_R3413_2015[0], Magma::IV_GOST_R3413_2015[1]];
        let mut v1 = Vec::from(r[0].to_be_bytes());
        v1.extend_from_slice(&r[1].to_be_bytes());
        assert_eq!(iv.to_be_bytes(), v1.as_slice());

        let magma = Magma::with_key(&CIPHER_KEY_RFC8891);

        let p1 = PLAINTEXT1_GOST_R3413_2015;
        let i1 = r[0];
        assert_eq!(i1, 0x1234567890abcdef_u64); 
        let o1 = magma.encrypt(i1);
        assert_eq!(o1, 0x49e910895a8336da_u64); 
        let c1 = p1 ^ o1;
        assert_eq!(c1, ENCRYPTED1_OFB_GOST_R3413_2015);

        r[0] = r[1];
        r[1] = o1;

        let p2 = PLAINTEXT2_GOST_R3413_2015;
        let i2 = r[0];
        assert_eq!(i2, 0x234567890abcdef1_u64); 
        let o2 = magma.encrypt(i2);
        assert_eq!(o2, 0xd612a348e78295bc_u64); 
        let c2 = p2 ^ o2;
        assert_eq!(c2, ENCRYPTED2_OFB_GOST_R3413_2015);

        r[0] = r[1];
        r[1] = o2;

        let p3 = PLAINTEXT3_GOST_R3413_2015;
        let i3 = r[0];
        assert_eq!(i3, 0x49e910895a8336da_u64); 
        let o3 = magma.encrypt(i3);
        assert_eq!(o3, 0xea60cb4c24a63032_u64); 
        let c3 = p3 ^ o3;
        assert_eq!(c3, ENCRYPTED3_OFB_GOST_R3413_2015);

        r[0] = r[1];
        r[1] = o3;

        let p4 = PLAINTEXT4_GOST_R3413_2015;
        let i4 = r[0];
        assert_eq!(i4, 0xd612a348e78295bc_u64); 
        let o4 = magma.encrypt(i4);
        assert_eq!(o4, 0x4136af23aafaa544_u64); 
        let c4 = p4 ^ o4;
        assert_eq!(c4, ENCRYPTED4_OFB_GOST_R3413_2015);
    }

    #[test]
    fn encrypt_ofb_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 37, Section A.2.3

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&PLAINTEXT1_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT2_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT3_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT4_GOST_R3413_2015.to_be_bytes());

        let mut magma = Magma::with_key(&CIPHER_KEY_RFC8891);

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        magma.set_iv(&Magma::IV_GOST_R3413_2015[..2]);

        let encrypted = OFB::encrypt(&mut magma, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&ENCRYPTED1_OFB_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED2_OFB_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED3_OFB_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED4_OFB_GOST_R3413_2015.to_be_bytes());
        assert_eq!(encrypted, expected);
    }

    #[test]
    fn decrypt_ofb_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 37, Section A.2.3

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&PLAINTEXT1_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT2_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT3_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT4_GOST_R3413_2015.to_be_bytes());

        let mut magma = Magma::with_key(&CIPHER_KEY_RFC8891);

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        magma.set_iv(&Magma::IV_GOST_R3413_2015[..2]);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&ENCRYPTED1_OFB_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED2_OFB_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED3_OFB_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED4_OFB_GOST_R3413_2015.to_be_bytes());

        let decrypted = OFB::decrypt(&mut magma, &encrypted);
        assert_eq!(decrypted, source);
    }
}
