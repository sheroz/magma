//! Block Cipher "Magma"
//!
//! Implemented and tested according to specifications:
//! 1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a **GOST R 34.12-2015**
//! 2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a **GOST 28147-89**
//! 3. Block Cipher Modes: [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
//!
//! [Cipher Modes](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
//! * **ECB** - Electronic Codebook Mode
//! * **CTR** - Counter Encryption Mode
//! * **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html), [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
//! * **OFB** - Output Feedback Mode
//! * **CBC** - Cipher Block Chaining Mode
//! * **CFB** - Cipher Feedback Mode
//! * **MAC** - Message Authentication Code Generation Mode

use std::collections::VecDeque;

use crate::*;
use crate::constants::*;
use crate::core::cipher_key::CipherKey;

/// Magma stream ciphering operations
pub struct MagmaStream {
    /// The core block-cipher 
    pub core: Magma,

    /// Stream ciphering context
    pub(crate) context: StreamContext,
}

#[derive(Clone)]
pub(crate) struct StreamContext {
    pub(crate) mode: CipherMode,
    pub(crate) operation: Option<CipherOperation>,
    pub(crate) iv: Vec<u64>,
    pub(crate) padded: bool,
    pub(crate) feedback: Feedback,
}

impl StreamContext {
    fn new(cipher_mode: CipherMode) -> Self {
        StreamContext {
            mode: cipher_mode,
            operation: None,
            iv: Vec::from(IV_GOST_R3413_2015),
            padded: false,
            feedback: Feedback::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Feedback {
    pub(crate) block: Option<u64>,
    pub(crate) vector: Option<VecDeque<u64>>,
}

impl Feedback {
    fn new() -> Self {
        Feedback {
            block: None,
            vector: None,
        }
    }
}

impl MagmaStream {

    /// Returns a new `MagmaStream` initialized with given cipher key and cipher mode
    ///
    /// Uses RFC7836 based substitution box
    ///
    /// # Arguments
    ///
    /// * `key` - array `[u32;8]` or `[u8;32]`
    /// * `cipher_mode` - a `CipherMode' value
    ///
    /// # Example
    ///
    /// ```
    /// use cipher_magma::{MagmaStream, CipherMode};
    /// let key: [u32;8] = [
    ///     0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ///     ];
    /// let magma = MagmaStream::new(key, CipherMode::CBC);
    /// ```
    /// Or
    ///
    /// ```
    /// use cipher_magma::{MagmaStream, CipherMode};
    /// let key: [u8;32] = [
    ///     0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ///     0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
    ///     0xfe, 0xff,
    ///     ];
    /// let magma = MagmaStream::new(key, CipherMode::CBC);
    /// ```
    pub fn new<T>(key: T, cipher_mode: CipherMode) -> Self
    where
        CipherKey: From<T>,
    {
        MagmaStream {
            core: Magma::with_key(key),
            context: StreamContext::new(cipher_mode),
        }
    }

    /// Sets the cipher key from array
    ///
    /// # Arguments
    ///
    /// * `key` - a `[u8;32]' or `[u32;8]` array
    pub fn set_key<T>(&mut self, key: T)
    where
        CipherKey: From<T>,
    {
        self.core.set_key(key);
        self.reset_feedback();
    }

    /// Sets the cipher mode
    ///
    /// # Arguments
    ///
    /// * `cipher_mode` - a `CipherMode' value
    pub fn set_mode(&mut self, cipher_mode: CipherMode) {
        self.context.mode = cipher_mode;
        self.reset_feedback();
    }

    /// Sets the substitution box
    ///
    /// # Arguments
    ///
    /// * `substitution_box` - A reference to `[u8;128]` array
    pub fn set_substitution_box(&mut self, substitution_box: &[u8; 128]) {
        self.core.set_substitution_box(substitution_box);
        self.reset_feedback();
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
    pub(crate) fn prepare_vector_ctr(&self) -> u64 {
        self.ensure_iv_not_empty();
        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // CTR Mode: Page 36, Section A.2.2, uses MSB(32) part of IV extended to 64bit with Initial Nonce
        // Initial Nonce: 0x00000000
        self.context.iv[0] & 0xffffffff_00000000
    }

    #[inline]
    pub(crate) fn ensure_iv_not_empty(&self) {
        if self.context.iv.is_empty() {
            panic!("Initialization vector is empty!");
        }
    }

    // check and update cipher context
    pub(crate) fn update_context(
        &mut self,
        cipher_operation: &CipherOperation,
        cipher_mode: &CipherMode,
    ) {
        if self.context.operation.as_ref() != Some(&cipher_operation)
            || self.context.mode != *cipher_mode
        {
            self.context.operation = Some(cipher_operation.clone());
            self.context.mode = cipher_mode.clone();
            self.reset_feedback();
        }
    }

    /// Resets the context of stream ciphering
    pub fn reset_context(&mut self) {
        let cipher_mode = self.context.mode.clone();
        self.context = StreamContext::new(cipher_mode);
    }

    /// Resets the feedback state of stream ciphering
    pub fn reset_feedback(&mut self) {
        self.context.feedback = Feedback::new();
    }

    /// Returns current `CipherMode` 
    pub fn get_mode(&self) -> CipherMode {
        return self.context.mode;
    }

    /// Returns encrypted vector as `Vec<u8>`
    ///
    /// # Arguments
    ///
    /// * `buf` - a slice of `&[u8]` input data
    /// * `cipher_mode` - reference to `CipherMode`
    pub fn encrypt(&mut self, buf: &[u8]) -> Vec<u8> {

        let cipher_mode = self.context.mode;

        // check and update feedback state
        self.update_context(&CipherOperation::Encrypt, &cipher_mode);

        match cipher_mode {
            CipherMode::ECB => ecb::encrypt(self, buf),
            CipherMode::CTR => ctr::encrypt(self, buf),
            CipherMode::CTR_ACPKM => ctr_acpkm::encrypt(self, buf),
            CipherMode::OFB => ofb::encrypt(self, buf),
            CipherMode::CBC => cbc::encrypt(self, buf),
            CipherMode::CFB => cfb::encrypt(self, buf),
            CipherMode::MAC => {
                panic!("CipherMode::MAC can not be used in encrypting operation!")
            }
        }
    }

    /// Returns a decrypted vector as `Vec<u8>`
    ///
    /// # Arguments
    ///
    /// * `buf` - a slice of `&[u8]` input data
    /// * `cipher_mode` - reference to `CipherMode`
    pub fn decrypt(&mut self, buf: &[u8]) -> Vec<u8> {

        let cipher_mode = self.context.mode;

        // check and update feedback state
        self.update_context(&CipherOperation::Decrypt, &cipher_mode);

        match cipher_mode {
            CipherMode::ECB => ecb::decrypt(self, buf),
            CipherMode::CTR => ctr::decrypt(self, buf),
            CipherMode::CTR_ACPKM => ctr_acpkm::decrypt(self, buf),
            CipherMode::OFB => ofb::decrypt(self, buf),
            CipherMode::CBC => cbc::decrypt(self, buf),
            CipherMode::CFB => cfb::decrypt(self, buf),
            CipherMode::MAC => {
                panic!("CipherMode::MAC can not be used in decrypting operation!")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_initialization() {
        let magma = MagmaStream::new([0;8],CipherMode::ECB);
        assert_eq!(magma.context.iv, IV_GOST_R3413_2015);
    }

    #[test]
    fn set_initialization_vector() {
        let mut magma = MagmaStream::new([0;8],CipherMode::ECB);
        let initialization_vector = vec![0x11223344_u64];
        magma.set_iv(&initialization_vector);
        assert_eq!(magma.context.iv, initialization_vector);
    }

    #[test]
    fn cipher_ecb_gost_r_34_13_2015() {
        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma =
            MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::ECB);
        let encrypted = magma.encrypt(&source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_ECB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_ECB.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.decrypt(&encrypted);
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

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::CTR);
        let encrypted = magma.encrypt(&source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CTR.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CTR.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.decrypt(&encrypted);
        assert_eq!(decrypted, source);
    }

    #[test]
    fn cipher_ctr_acpkm_r_1323565_1_017_2018() {
        // Test Vectors CTR-ACPKM
        // Р 1323565.1.017—2018
        // https://standartgost.ru/g/%D0%A0_1323565.1.017-2018
        // Page 11

        use crypto_vectors::gost::r1323565_1_017_2018::ctr_acpkm;

        let mut magma = MagmaStream::new(ctr_acpkm::CIPHER_KEY.clone(), CipherMode::CTR_ACPKM);

        let encrypted = magma.encrypt(&ctr_acpkm::PLAINTEXT);
        assert!(!encrypted.is_empty());

        assert_eq!(encrypted, ctr_acpkm::CIPHERTEXT);

        let decrypted = magma.decrypt(&encrypted);
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

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::OFB);

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
        magma.set_iv(&IV_GOST_R3413_2015[..2]);

        let encrypted = magma.encrypt(&source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_OFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_OFB.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.decrypt(&encrypted);
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

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::CBC);

        let encrypted = magma.encrypt(&source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CBC.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CBC.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.decrypt(&encrypted);
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

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::CFB);

        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // CFB Mode: Page 39, Section A.2.5, uses MSB(128) part of IV
        magma.set_iv(&IV_GOST_R3413_2015[..2]);

        let encrypted = magma.encrypt(&source);
        assert!(!encrypted.is_empty());

        let mut expected = Vec::<u8>::new();
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT1_CFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT2_CFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT3_CFB.to_be_bytes());
        expected.extend_from_slice(&r3413_2015::CIPHERTEXT4_CFB.to_be_bytes());
        assert_eq!(encrypted, expected);

        let decrypted = magma.decrypt(&encrypted);
        assert_eq!(decrypted, source);
    }
}
