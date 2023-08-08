use std::collections::VecDeque;
use crate::*;

pub struct Stream {
    pub core: Core,
    pub (crate) context: Context,
}

#[derive(Clone)]
struct Context {
    operation: Option<CipherOperation>,
    mode: Option<CipherMode>,
    iv: Vec<u64>,
    padded: bool,
    feedback: Feedback
}

impl Context {
    fn new() -> Self {
        Context { operation: None, mode: None, iv: Vec::from(IV_GOST_R3413_2015), padded: false, feedback: Feedback::new() }
    }
}

#[derive(Clone)]
struct Feedback {
    block: Option<u64>,
    vector: Option<VecDeque<u64>>
}

impl Feedback {
    fn new() -> Self {
        Feedback { block: None, vector: None }
    } 
}

impl Stream {
    pub fn new() -> Self {
        Stream {
            core: Core::new(),
            context: Context::new()
        }
    }
    /// Sets the Initialization Vector (IV)
    ///
    /// # Arguments
    ///
    /// * `iv` - A slice to `&[u64]` array
    ///
    /// **Attention**: `CTR` Mode uses only the MSB(32) part of IV
    pub fn set_iv(&mut self, iv: &[u64]) {
        self.context.iv = Vec::from(iv);
        self.reset_feedback();
    }

    #[inline]
    fn prepare_vector_ctr(&self) -> u64 {
        self.ensure_iv_not_empty();
        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // CTR Mode: Page 36, Section A.2.2, uses MSB(32) part of IV extended to 64bit with Initial Nonce
        // Initial Nonce: 0x00000000
        self.context.iv[0] & 0xffffffff_00000000
    }

    #[inline]
    fn ensure_iv_not_empty(&self) {
        if self.context.iv.is_empty() {
            panic!("Initialization vector is empty!");
        }
    }

    // check and update cipher context
    fn update_context(&mut self, cipher_operation: &CipherOperation, cipher_mode: &CipherMode) {
        if self.context.operation.as_ref() != Some(&cipher_operation)
            || self.context.mode.as_ref() != Some(&cipher_mode)
        {
            self.context.operation = Some(cipher_operation.clone());
            self.context.mode = Some(cipher_mode.clone());
            self.reset_feedback();
        }
    }

    /// Resets the context of stream ciphering
    pub fn reset_context(&mut self) {
        self.context = Context::new();
    }


    /// Resets the feedback state of stream ciphering
    pub fn reset_feedback(&mut self) {
        self.context.feedback = Feedback::new();
    }

    /// Returns resulting vector as `Vec<u8>`
    ///
    /// # Arguments
    ///
    /// * `buf` - a slice of `&[u8]` input data
    /// * `cipher_operation` - reference to `CipherOperation`
    /// * `cipher_mode` - reference to `CipherMode`
    pub fn cipher(
        &mut self,
        buf: &[u8],
        cipher_operation: &CipherOperation,
        cipher_mode: &CipherMode,
    ) -> Vec<u8> {

        // check and update feedback state
        self.update_context(cipher_operation, cipher_mode);

        match cipher_operation {
            CipherOperation::Encrypt => match cipher_mode {
                CipherMode::ECB => ecb::encrypt(self.core, buf),
                CipherMode::CTR => ctr::encrypt(self, buf),
                CipherMode::CTR_ACPKM => ctr_acpkm::encrypt(self, buf),
                CipherMode::OFB => ofb::encrypt(self, buf),
                CipherMode::CBC => cbc::encrypt(self, buf),
                CipherMode::CFB => cfb::encrypt(self, buf),
                CipherMode::MAC => {
                    panic!("CipherMode::MAC can not be used in encrypting operation!")
                }
            },
            CipherOperation::Decrypt => match cipher_mode {
                CipherMode::ECB => ecb::decrypt(self, buf),
                CipherMode::CTR => ctr::decrypt(self, buf),
                CipherMode::CTR_ACPKM => ctr_acpkm::decrypt(self, buf),
                CipherMode::OFB => ofb::decrypt(self, buf),
                CipherMode::CBC => cbc::decrypt(self, buf),
                CipherMode::CFB => cfb::decrypt(self, buf),
                CipherMode::MAC => {
                    panic!("CipherMode::MAC can not be used in decrypting operation!")
                }
            },
            CipherOperation::MessageAuthentication => match cipher_mode {
                CipherMode::MAC => mac::calculate(self, buf).to_be_bytes().to_vec(),
                _ => panic!("Only CipherMode::MAC can be used in MessageAuthentication!"),
            },
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_initialization() {
        let stream = Stream::new();
        assert_eq!(stream.context.iv, IV_GOST_R3413_2015);
    }

    #[test]
    fn set_initialization_vector() {
        let mut stream = Stream::new();
        let initialization_vector = vec![0x11223344_u64];
        stream.set_iv(&initialization_vector);
        assert_eq!(stream.context.iv, initialization_vector);
    }

    #[test]
    fn cipher_ecb_gost_r_34_13_2015() {
        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());
        let encrypted = magma.cipher(&source, &CipherOperation::Encrypt, &CipherMode::ECB);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_ECB.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &CipherMode::ECB);
        assert_eq!(decrypted, source);
    }

    #[test]
    fn cipher_ctr_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 36, Section A.2.2

        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());
        let encrypted = magma.cipher(&source, &CipherOperation::Encrypt, &CipherMode::CTR);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CTR.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &CipherMode::CTR);
        assert_eq!(decrypted, source);
    }

    #[test]
    fn cipher_ctr_acpkm_r_1323565_1_017_2018() {
        // Test Vectors CTR-ACPKM
        // Р 1323565.1.017—2018
        // https://standartgost.ru/g/%D0%A0_1323565.1.017-2018
        // Page 11

        use crypto_vectors::gost::r1323565_1_017_2018::ctr_acpkm;

        let mut magma = Magma::with_key(ctr_acpkm::CIPHER_KEY.clone());

        let encrypted = magma.cipher(
            &ctr_acpkm::PLAINTEXT,
            &CipherOperation::Encrypt,
            &CipherMode::CTR_ACPKM,
        );
        assert!(!encrypted.is_empty());

        assert_eq!(encrypted, ctr_acpkm::CIPHERTEXT);

        let decrypted = magma.cipher(
            &encrypted,
            &CipherOperation::Decrypt,
            &CipherMode::CTR_ACPKM,
        );
        assert_eq!(decrypted, ctr_acpkm::PLAINTEXT);
    }

    #[test]
    fn cipher_ofb_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 37, Section A.2.3

        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        magma.set_iv(&Magma::IV_GOST_R3413_2015[..2]);

        let encrypted = magma.cipher(&source, &CipherOperation::Encrypt, &CipherMode::OFB);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_OFB.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &CipherMode::OFB);
        assert_eq!(decrypted, source);
    }

    #[test]
    fn cipher_cbc_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 38, Section A.2.4
        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());
        let encrypted = magma.cipher(&source, &CipherOperation::Encrypt, &CipherMode::CBC);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CBC.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &CipherMode::CBC);
        assert_eq!(decrypted, source);
    }

    #[test]
    fn cipher_cfb_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 39, Section A.2.5
        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // CFB Mode: Page 39, Section A.2.5, uses MSB(128) part of IV
        magma.set_iv(&Magma::IV_GOST_R3413_2015[..2]);

        let encrypted = magma.cipher(&source, &CipherOperation::Encrypt, &CipherMode::CFB);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CFB.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &CipherMode::CFB);
        assert_eq!(decrypted, source);
    }

    #[test]
    fn cipher_mac_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 40, Section A.2.6

        use crypto_vectors::gost::r3413_2015;
        let mut magma = Magma::with_key(r3413_2015::CIPHER_KEY.clone());

        let mut src_buf = Vec::<u8>::new();
        src_buf.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        src_buf.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        src_buf.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        src_buf.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mac_vec = magma.cipher(
            &src_buf,
            &CipherOperation::MessageAuthentication,
            &CipherMode::MAC,
        );
        assert_eq!(mac_vec.len(), 4);

        let mut array_u8 = [0u8; 4];
        mac_vec
            .iter()
            .enumerate()
            .for_each(|t| array_u8[t.0] = *t.1);
        let mac = u32::from_be_bytes(array_u8);
        assert_eq!(mac, r3413_2015::MAC);
    }
}