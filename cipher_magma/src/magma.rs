//! **Block Cipher "Magma"**
//!
//! Implemented and tested according to specifications:
//! 1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015
//! 2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89
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

/*
    RFC 5831: GOST R 34.11-94
    hash function:
    https://datatracker.ietf.org/doc/rfc5831/
    https://datatracker.ietf.org/doc/html/rfc4357
    https://en.wikipedia.org/wiki/GOST_(hash_function)

    GOST R 34.11-94
    GOST 34.311-95
    GOST hash function
    GOST 28147-89 IMIT
*/

pub mod cipher_mode;
pub mod cipher_operation;
pub mod utils;

use std::collections::VecDeque;

use cipher_mode::{cbc, cfb, ctr, ctr_acpkm, ecb, mac, ofb, CipherMode};
use cipher_operation::CipherOperation;

/// Block Cipher "Magma"
pub struct Magma {
    cipher_key: [u32; 8],
    round_keys: [u32; 32],
    substitution_box: [u8; 128],
    iv: Vec<u64>,
    context: Context,
}

#[derive(Clone)]
struct Context {
    operation: Option<CipherOperation>,
    mode: Option<CipherMode>,
    padded: bool,
    feedback: Feedback
}
impl Context {
    fn new() -> Self {
        Context { operation: None, mode: None, padded: false, feedback: Feedback::new() }
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

impl Magma {
    /// Substitution Box (S-Box) data according to [Appendix C. RFC7836](https://datatracker.ietf.org/doc/html/rfc7836#appendix-C)
    ///
    /// Parameter set: id-tc26-gost-28147-param-Z
    pub const SUBSTITUTION_BOX_RFC7836: [u8; 128] = [
        0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1, 0x6, 0x8,
        0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF, 0xB, 0x3, 0x5, 0x8,
        0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0, 0xC, 0x8, 0x2, 0x1, 0xD, 0x4,
        0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB, 0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD,
        0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC, 0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7,
        0x8, 0x1, 0x4, 0x3, 0xE, 0x0, 0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0,
        0xD, 0xA, 0x3, 0x7, 0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC,
        0xB, 0x2,
    ];

    /// Substitution Box (S-Box) data according to [RFC5831](https://datatracker.ietf.org/doc/html/rfc5831#section-7.1)
    ///
    /// As per [Appendix B of RFC8891](https://datatracker.ietf.org/doc/html/rfc8891.html#section-appendix.b) data values converted
    /// from little-endian to big-endian format.
    ///
    /// OID: 1.2.643.2.2.30.0
    pub const SUBSTITUTION_BOX_RFC5831: [u8; 128] = [
        0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3, 0xE, 0xB,
        0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9, 0x5, 0x8, 0x1, 0xD,
        0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB, 0x7, 0xD, 0xA, 0x1, 0x0, 0x8,
        0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3, 0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8,
        0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2, 0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6,
        0x8, 0x5, 0x9, 0xC, 0xF, 0xE, 0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7,
        0x6, 0x8, 0x2, 0xC, 0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB,
        0x8, 0xC,
    ];

    /// Initialization Vector (IV)
    ///  
    /// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
    ///
    /// CTR Mode: Page 36, Section A.2.2, uses MSB(32) part of IV
    ///
    /// OFB Mode: Page 37, Section A.2.3, uses MSB(128) part of IV
    ///
    /// CFB Mode: Page 39, Section A.2.5, uses MSB(128) part of IV
    pub const IV_GOST_R3413_2015: [u64; 3] = [
        0x1234567890abcdef_u64,
        0x234567890abcdef1_u64,
        0x34567890abcdef12_u64,
    ];

    /// Р 1323565.1.017—2018
    ///
    /// Section size N
    ///
    /// Page 7, CTR-ACPKM
    const CTR_ACPKM_SECTION_SIZE_N: usize = 128;

    /// Р 1323565.1.017—2018
    ///
    /// Constant D for ACPKM function
    ///
    /// Page 8, CTR-ACPKM
    const CTR_ACPKM_D: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
        0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D,
        0x9E, 0x9F,
    ];

    /// Returns a new Magma by using RFC7836 based substitution box
    ///
    /// # Example
    /// ```
    /// use cipher_magma::Magma;
    /// let magma = Magma::new();
    /// ```
    pub fn new() -> Magma {
        Magma {
            cipher_key: [0u32; 8],
            round_keys: [0u32; 32],
            substitution_box: Magma::SUBSTITUTION_BOX_RFC7836.clone(),
            iv: Vec::from(Magma::IV_GOST_R3413_2015),
            context: Context::new(),
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

    /// Returns a new Magma initialized with given cipher key
    ///
    /// Uses RFC7836 based substitution box
    ///
    /// # Arguments
    ///
    /// * `cipher_key` - A reference to `[u32;8]` array
    ///
    /// # Example
    /// ```
    /// use cipher_magma::Magma;
    /// let cipher_key: [u32;8] = [
    ///     0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ///     ];
    ///
    /// let magma = Magma::with_key_u32(&cipher_key);
    /// ```
    pub fn with_key_u32(cipher_key: &[u32; 8]) -> Magma {
        let mut engine = Magma::new();
        engine.set_key_u32(cipher_key);
        engine
    }

    /// Returns a new Magma initialized with given cipher key
    ///
    /// Uses RFC7836 based substitution box
    ///
    /// # Arguments
    ///
    /// * `cipher_key` - A reference to `[u8;32]` array
    ///
    /// # Example
    /// ```
    /// use cipher_magma::Magma;
    /// let cipher_key: [u8; 32] = [
    ///    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ///    0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
    ///    0xfe, 0xff,
    /// ];
    ///
    /// let magma = Magma::with_key_u8(&cipher_key);
    /// ```
    pub fn with_key_u8(cipher_key: &[u8; 32]) -> Magma {
        let mut engine = Magma::new();
        engine.set_key_u8(cipher_key);
        engine
    }

    /// Sets the substitution box
    ///
    /// # Arguments
    ///
    /// * `substitution_box` - A reference to `[u8;128]` array
    pub fn set_substitution_box(&mut self, substitution_box: &[u8; 128]) {
        self.substitution_box.copy_from_slice(substitution_box);
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
        self.iv = Vec::from(iv);
        self.reset_feedback();
    }

    #[inline]
    fn prepare_vector_ctr(&self) -> u64 {
        self.ensure_iv_not_empty();
        // [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
        // CTR Mode: Page 36, Section A.2.2, uses MSB(32) part of IV extended to 64bit with Initial Nonce
        // Initial Nonce: 0x00000000
        self.iv[0] & 0xffffffff_00000000
    }

    #[inline]
    fn ensure_iv_not_empty(&self) {
        if self.iv.is_empty() {
            panic!("Initialization vector is empty!");
        }
    }
    /// Sets the cipher key from `[u32;8]` array
    ///
    /// # Arguments
    ///
    /// * `cipher_key` - A reference to `[u32;8]` array
    pub fn set_key_u32(&mut self, cipher_key: &[u32; 8]) {
        self.cipher_key.clone_from(cipher_key);
        self.prepare_round_keys();
        self.reset_feedback();
    }

    /// Sets the cipher key from slice of u8 bytes
    ///
    /// # Arguments
    ///
    /// * `cipher_key_bytes` - A `&[u8]` slice with 32 byte elements
    pub fn set_key_u8(&mut self, cipher_key_bytes: &[u8]) {
        assert!(cipher_key_bytes.len() == 32);

        let mut array_u8 = [0u8; 4];
        for (index, chunk) in cipher_key_bytes.chunks(4).enumerate() {
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            self.cipher_key[index] = u32::from_be_bytes(array_u8);
        }

        self.prepare_round_keys();
        self.reset_feedback();
    }

    /// Prepares [round keys](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.3) from the cipher key
    fn prepare_round_keys(&mut self) {
        const ROUND_KEY_POSITION: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3,
            2, 1, 0,
        ];

        for index in 0..32 {
            let round_key_position = ROUND_KEY_POSITION[index] as usize;
            self.round_keys[index] = self.cipher_key[round_key_position];
        }
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `t: V_32 -> V_32`
    #[inline]
    fn transformation_t(&self, a: u32) -> u32 {
        let mut res: u32 = 0;
        let mut shift_count = 0;
        for i in 0..8 {
            let v = (a >> shift_count) & 0xF;
            let s = self.substitution_box[(i * 16 + v) as usize] as u32;
            res |= s << shift_count;
            shift_count += 4;
        }
        res
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `g[k]: V_32 -> V_32`
    #[inline]
    fn transformation_g(&self, k: u32, a: u32) -> u32 {
        let res = self.transformation_t(((k as u64) + (a as u64)) as u32);
        res.rotate_left(11)
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `G[k]: V_32[*]V_32 -> V_32[*]V_32`
    #[inline]
    fn transformation_big_g(&self, k: u32, a_1: u32, a_0: u32) -> (u32, u32) {
        (a_0, self.transformation_g(k, a_0) ^ a_1)
    }

    /// Returns [encrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.1) as `u64` value
    ///
    /// # Arguments
    ///
    /// * `block_in` - a plaintext value as `u64`
    #[inline]
    pub fn encrypt(&self, block_in: u64) -> u64 {
        // split the input block into u32 parts
        let (mut a_1, mut a_0) = utils::u64_split(block_in);

        // crypto transformations
        let mut round = 0;
        while round < 32 {
            (a_1, a_0) = self.transformation_big_g(self.round_keys[round], a_1, a_0);
            round += 1;
        }

        // join u32 parts into u64 block
        utils::u32_join(a_0, a_1)
    }

    /// Returns [decrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.2) as `u64` value
    ///
    /// # Arguments
    ///
    /// * `block_in` - a ciphertext value as `u64`
    #[inline]
    pub fn decrypt(&self, block_in: u64) -> u64 {
        // split the input block into u32 parts
        let (mut b_1, mut b_0) = utils::u64_split(block_in);

        // crypto transformations
        let mut round = 32;
        while round != 0 {
            round -= 1;
            (b_1, b_0) = self.transformation_big_g(self.round_keys[round], b_1, b_0);
        }

        // join u32 parts into u64 block
        utils::u32_join(b_0, b_1)
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
                CipherMode::ECB => ecb::encrypt(self, buf),
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
    fn has_padding() {
        assert_eq!(CipherMode::ECB.has_padding(), true);
        assert_eq!(CipherMode::CTR.has_padding(), false);
        assert_eq!(CipherMode::CTR_ACPKM.has_padding(), false);
        assert_eq!(CipherMode::OFB.has_padding(), false);
        assert_eq!(CipherMode::CBC.has_padding(), true);
        assert_eq!(CipherMode::CFB.has_padding(), false);
        assert_eq!(CipherMode::MAC.has_padding(), true);
    }

    #[test]
    fn default_initialization() {
        let magma = Magma::new();
        assert_eq!(magma.cipher_key, [0u32; 8]);
        assert_eq!(magma.round_keys, [0u32; 32]);
        assert_eq!(magma.substitution_box, Magma::SUBSTITUTION_BOX_RFC7836);
        assert_eq!(magma.iv, Magma::IV_GOST_R3413_2015);
    }

    #[test]
    fn set_initialization_vector() {
        let mut magma = Magma::new();
        let initialization_vector = vec![0x11223344_u64];
        magma.set_iv(&initialization_vector);
        assert_eq!(magma.iv, initialization_vector);
    }

    #[test]
    fn with_key_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(magma.cipher_key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn set_key_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let mut magma = Magma::new();
        magma.set_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(magma.cipher_key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn set_keys_from_big_endian_u8_array_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let mut magma = Magma::new();
        magma.set_key_u8(&rfc8891::CIPHER_KEY_U8_ARRAY);
        assert_eq!(magma.cipher_key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn with_keys_from_big_endian_u8_array_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key_u8(&rfc8891::CIPHER_KEY_U8_ARRAY);
        assert_eq!(magma.cipher_key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn transformation_t_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.1

        use crypto_vectors::gost::rfc8891;
        let t = rfc8891::TRANSFORMATION_T;

        let magma = Magma::new();
        assert_eq!(magma.transformation_t(t[0].0), t[0].1);
        assert_eq!(magma.transformation_t(t[1].0), t[1].1);
        assert_eq!(magma.transformation_t(t[2].0), t[2].1);
        assert_eq!(magma.transformation_t(t[3].0), t[3].1);
    }

    #[test]
    fn transformation_g_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.2

        use crypto_vectors::gost::rfc8891;
        let g = rfc8891::TRANSFORMATION_G;

        let magma = Magma::new();

        assert_eq!(magma.transformation_g(g[0].0 .0, g[0].0 .1), g[0].1);
        assert_eq!(magma.transformation_g(g[1].0 .0, g[1].0 .1), g[1].1);
        assert_eq!(magma.transformation_g(g[2].0 .0, g[2].0 .1), g[2].1);
        assert_eq!(magma.transformation_g(g[3].0 .0, g[3].0 .1), g[3].1);
    }

    #[test]
    fn round_keys_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.3

        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(magma.round_keys, rfc8891::ROUND_KEYS);
    }

    #[test]
    fn transformation_big_g_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.4

        use crypto_vectors::gost::rfc8891;
        let big_g = rfc8891::TRANSFORMATION_BIG_G;

        let magma = Magma::with_key_u32(&rfc8891::CIPHER_KEY);

        let (mut a_1, mut a_0) = utils::u64_split(rfc8891::PLAINTEXT);

        for round in 0..32 {
            (a_1, a_0) = magma.transformation_big_g(magma.round_keys[round], a_1, a_0);
            assert_eq!(big_g[round], (a_1, a_0));
        }
    }

    #[test]
    fn encrypt_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-test-encryption

        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(magma.encrypt(rfc8891::PLAINTEXT), rfc8891::CIPHERTEXT);
    }

    #[test]
    fn decrypt_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-test-decryption

        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(magma.decrypt(rfc8891::CIPHERTEXT), rfc8891::PLAINTEXT);
    }

    #[test]
    fn encrypt_rfc5830() {
        // Test vectors for GOST 28147-89
        // https://www.rfc-editor.org/rfc/rfc5831#section-7

        use crypto_vectors::gost::rfc5831;

        let mut magma = Magma::new();
        magma.set_substitution_box(&Magma::SUBSTITUTION_BOX_RFC5831);

        magma.set_key_u32(&rfc5831::CIPHER_KEY1);
        assert_eq!(magma.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT1);

        magma.set_key_u32(&rfc5831::CIPHER_KEY2);
        assert_eq!(magma.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT2);

        magma.set_key_u32(&rfc5831::CIPHER_KEY3);
        assert_eq!(magma.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT3);

        magma.set_key_u32(&rfc5831::CIPHER_KEY4);
        assert_eq!(magma.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT4);
    }

    #[test]
    fn decrypt_rfc5830() {
        // Test vectors for GOST 28147-89
        // https://www.rfc-editor.org/rfc/rfc5831#section-7

        use crypto_vectors::gost::rfc5831;

        let mut magma = Magma::new();
        magma.set_substitution_box(&Magma::SUBSTITUTION_BOX_RFC5831);

        magma.set_key_u32(&rfc5831::CIPHER_KEY1);
        assert_eq!(magma.decrypt(rfc5831::CIPHERTEXT1), rfc5831::PLAINTEXT);

        magma.set_key_u32(&rfc5831::CIPHER_KEY2);
        assert_eq!(magma.decrypt(rfc5831::CIPHERTEXT2), rfc5831::PLAINTEXT);

        magma.set_key_u32(&rfc5831::CIPHER_KEY3);
        assert_eq!(magma.decrypt(rfc5831::CIPHERTEXT3), rfc5831::PLAINTEXT);

        magma.set_key_u32(&rfc5831::CIPHER_KEY4);
        assert_eq!(magma.decrypt(rfc5831::CIPHERTEXT4), rfc5831::PLAINTEXT);
    }

    #[test]
    fn encrypt_gost_r_34_13_2015_ecb() {
        use crypto_vectors::gost::r3413_2015;

        let magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);
        assert_eq!(
            magma.encrypt(r3413_2015::PLAINTEXT1),
            r3413_2015::CIPHERTEXT1_ECB
        );
        assert_eq!(
            magma.encrypt(r3413_2015::PLAINTEXT2),
            r3413_2015::CIPHERTEXT2_ECB
        );
        assert_eq!(
            magma.encrypt(r3413_2015::PLAINTEXT3),
            r3413_2015::CIPHERTEXT3_ECB
        );
        assert_eq!(
            magma.encrypt(r3413_2015::PLAINTEXT4),
            r3413_2015::CIPHERTEXT4_ECB
        );
    }

    #[test]
    fn decrypt_gost_r_34_13_2015_ecb() {
        use crypto_vectors::gost::r3413_2015;
        let magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);
        assert_eq!(
            magma.decrypt(r3413_2015::CIPHERTEXT1_ECB),
            r3413_2015::PLAINTEXT1
        );
        assert_eq!(
            magma.decrypt(r3413_2015::CIPHERTEXT2_ECB),
            r3413_2015::PLAINTEXT2
        );
        assert_eq!(
            magma.decrypt(r3413_2015::CIPHERTEXT3_ECB),
            r3413_2015::PLAINTEXT3
        );
        assert_eq!(
            magma.decrypt(r3413_2015::CIPHERTEXT4_ECB),
            r3413_2015::PLAINTEXT4
        );
    }

    #[test]
    fn cipher_ecb_gost_r_34_13_2015() {
        use crypto_vectors::gost::r3413_2015;
        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);
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

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);
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

        let mut magma = Magma::new();
        magma.set_key_u8(&ctr_acpkm::CIPHER_KEY);

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

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);

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

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);
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

        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);

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
        let mut magma = Magma::with_key_u32(&r3413_2015::CIPHER_KEY);

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
