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

pub mod core;
pub mod stream;
pub mod constants;
pub mod cipher_key;
pub mod cipher_mode;
pub mod cipher_operation;
pub mod utils;

use crate::*;
use crate::magma::cipher_key::CipherKey;

/// Block Cipher "Magma"
pub struct Magma {
    pub stream: Stream
}

impl Magma {

    /// Returns a new Magma by using RFC7836 based substitution box
    ///
    /// # Example
    /// ```
    /// use cipher_magma::Magma;
    /// let magma = Magma::new();
    /// ```
    pub fn new() -> Self {
        Magma {
            stream: Stream::new(),
        }
    }

    /// Returns a new Magma initialized with given cipher key
    ///
    /// Uses RFC7836 based substitution box
    ///
    /// # Arguments
    ///
    /// * `key` - array `[u32;8]` or `[u8;32]`
    ///
    /// # Example
    /// 
    /// ```
    /// use cipher_magma::Magma;
    /// let key: [u32;8] = [
    ///     0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ///     ];
    ///
    /// let magma = Magma::with_key(key);
    /// ```
    /// Or
    /// 
    /// ```
    /// use cipher_magma::Magma;
    /// let key: [u8;32] = [
    ///     0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ///     0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
    ///     0xfe, 0xff,
    ///     ];
    ///
    /// let magma = Magma::with_key(key);
    /// ```
    pub fn with_key <T> (key: T) -> Magma
        where CipherKey: From<T> {
        let mut engine = Magma::new();
        engine.set_key(key);
        engine
    }
  
    /// Sets the cipher key from array
    ///
    /// # Arguments
    ///
    /// * `key` - a `[u8;32]' or `[u32;8]` array
    pub fn set_key <T> (&mut self, key: T) where CipherKey: From<T> {
        let cipher_key = CipherKey::from(key);
        match cipher_key {
            CipherKey::ArrayU8(k) => { self.stream.core.set_key_u8(&k) }
            CipherKey::ArrayU32(k) => { self.stream.core.set_key_u32(&k) }, 
        };
        self.stream.reset_feedback();
    }

    /// Sets the substitution box
    ///
    /// # Arguments
    ///
    /// * `substitution_box` - A reference to `[u8;128]` array
    pub fn set_substitution_box(&mut self, substitution_box: &[u8; 128]) {
        self.stream.core.set_substitution_box(substitution_box);
        self.stream.reset_feedback();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_key_generic_u32_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key(rfc8891::CIPHER_KEY.clone());
        assert_eq!(magma.stream.core.key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn with_key_generic_u8_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let magma = Magma::with_key(rfc8891::CIPHER_KEY_U8_ARRAY.clone());
        assert_eq!(magma.stream.core.key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn set_key_generic_u32() {
        use crypto_vectors::gost::rfc8891;
        let mut magma = Magma::new();
        magma.set_key(rfc8891::CIPHER_KEY.clone());
        assert_eq!(magma.stream.core.key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn set_key_generic_u8() {
        use crypto_vectors::gost::rfc8891;
        let mut magma = Magma::new();
        magma.set_key(rfc8891::CIPHER_KEY_U8_ARRAY.clone());
        assert_eq!(magma.stream.core.key, rfc8891::CIPHER_KEY);
    }
}
