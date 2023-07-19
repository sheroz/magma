/// **Cipher Mode**
/// 
/// # Supported Cipher Modes
/// 
/// * **ECB** - Electronic Codebook Mode
/// * **CTR** - Counter Encryption Mode
/// * **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html)
/// * **OFB** - Output Feedback Mode
/// * **CBC** - Cipher Block Chaining Mode
/// * **CFB** - Cipher Feedback Mode
/// * **MAC** - Message Authentication Code Generation Mode
/// 
/// [Cipher Modes](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// [CTR-ACPKM](https://www.rfc-editor.org/rfc/rfc8645.html)
pub enum CipherMode {
    /// Electronic Codebook (ECB) Mode
    ECB, 

    /// Counter Encryption (CTR) Mode
    CTR, 

    /// Counter Encryption (CTR-ACPKM) Mode
    #[allow(non_camel_case_types)]
    CTR_ACPKM,

    /// Output Feedback (OFB) Mode
    OFB,

    /// Cipher Block Chaining (CBC) Mode
    CBC,

    /// Cipher Feedback Mode (CFB)
    CFB,

    /// Message Authentication Code (MAC) Generation Mode
    MAC 
}

impl CipherMode {
    /// Returns a boolean value indicating whether the `cipher_mode` requires padding
    /// 
    /// Some cipher modes require the size of the input plaintext to be multiple of the block size,
    /// so input plaintext may have to be padded before encryption to bring it to the required length.
    /// 
    /// # Argument
    /// * cipher_mode - a reference to `CipherMode`
    pub fn has_padding(&self) -> bool
    {
        match *self {
            CipherMode::CTR => false,
            CipherMode::CTR_ACPKM => false,
            CipherMode::OFB => false,
            CipherMode::CFB => false,
            _ => true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CipherMode;

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
}
