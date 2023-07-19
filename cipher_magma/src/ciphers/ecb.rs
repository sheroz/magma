use crate::Magma;
use crate::core::CipherBuffer;

pub struct ECB;

impl CipherBuffer for ECB {
    /// Returns encrypted result as `Vec<u8>`
    /// 
    /// Implements buffer encrypting in Electronic Codebook (ECB) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 13, Section 5.1.1
    fn encrypt(core: &Magma, buf: &[u8]) -> Vec<u8> {
        let m_invoke = Magma::encrypt;
        ECB::cipher_ecb(core, buf, m_invoke)
    }

    /// Returns decrypted result as `Vec<u8>`
    /// 
    /// Implements buffer decrypting in Electronic Codebook (ECB) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 13, Section 5.1.2
    fn decrypt(core: &Magma, buf: &[u8]) -> Vec<u8> {
        let m_invoke = Magma::decrypt;
        ECB::cipher_ecb(core, buf, m_invoke)
    }
}

impl ECB {
    /// Returns encrypted/decrypted result as `Vec<u8>`
    /// 
    /// Implements Electronic Codebook (ECB) Mode
    /// 
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    /// 
    /// Page 13, Section 5.1
    fn cipher_ecb(core: &Magma, buf: &[u8], m_invoke: fn(&Magma, u64) -> u64) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(buf.len());
        for chunk in buf.chunks(8) {
            let mut array_u8 = [0u8;8];
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            let block = u64::from_be_bytes(array_u8);
            let output = m_invoke(&core, block);
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
    // Encrypting in ECB Mode
    // Page 35, Section: A.2.1
    const ENCRYPTED1_ECB_GOST_R3413_2015: u64 = 0x2b073f0494f372a0_u64;
    const ENCRYPTED2_ECB_GOST_R3413_2015: u64 = 0xde70e715d3556e48_u64;
    const ENCRYPTED3_ECB_GOST_R3413_2015: u64 = 0x11d8d9e9eacfbc1e_u64;
    const ENCRYPTED4_ECB_GOST_R3413_2015: u64 = 0x7c68260996c67efb_u64;            

    #[test]
    fn encrypt_ecb_gost_r_34_13_2015() {
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&PLAINTEXT1_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT2_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT3_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT4_GOST_R3413_2015.to_be_bytes());

        let magma = Magma::with_key(&CIPHER_KEY_RFC8891);
        let encrypted = ECB::encrypt(&magma, &source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&ENCRYPTED1_ECB_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED2_ECB_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED3_ECB_GOST_R3413_2015.to_be_bytes());
        expected.extend_from_slice(&ENCRYPTED4_ECB_GOST_R3413_2015.to_be_bytes());
        assert_eq!(encrypted, expected);
    }
    
    #[test]
    fn decrypt_ecb_gost_r_34_13_2015() {
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&PLAINTEXT1_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT2_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT3_GOST_R3413_2015.to_be_bytes());
        source.extend_from_slice(&PLAINTEXT4_GOST_R3413_2015.to_be_bytes());

        let magma = Magma::with_key(&CIPHER_KEY_RFC8891);

        let mut encrypted = Vec::<u8>::new();
        encrypted.extend_from_slice(&ENCRYPTED1_ECB_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED2_ECB_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED3_ECB_GOST_R3413_2015.to_be_bytes());
        encrypted.extend_from_slice(&ENCRYPTED4_ECB_GOST_R3413_2015.to_be_bytes());

        let decrypted = ECB::decrypt(&magma, &encrypted);
        assert_eq!(decrypted, source);
    }    
}