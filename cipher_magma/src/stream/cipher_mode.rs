//! Cipher Mode
//! 
//! [Cipher Modes](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
//! 
//! * **ECB** - Electronic Codebook Mode
//! * **CTR** - Counter Encryption Mode
//! * **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html), [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
//! * **OFB** - Output Feedback Mode
//! * **CBC** - Cipher Block Chaining Mode
//! * **CFB** - Cipher Feedback Mode
//! * **MAC** - Message Authentication Code Generation Mode

pub mod ecb;
pub mod ctr;
pub mod ctr_acpkm;
pub mod ofb;
pub mod cbc;
pub mod cfb;
pub mod mac;

/// Cipher Mode
#[derive(PartialEq, Clone, Copy)]
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
    /// Returns a boolean value indicating whether the cipher mode requires padding
    /// 
    /// Some cipher modes require the size of the input plaintext to be multiple of the block size,
    /// so input plaintext may have to be padded before encryption to bring it to the required length.
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

impl ToString for CipherMode {
    fn to_string(&self) -> String {
        match *self {
            CipherMode::ECB => "ECB".to_string(),
            CipherMode::CTR => "CTR".to_string(),
            CipherMode::CTR_ACPKM => "CTR_ACPKM".to_string(),
            CipherMode::OFB => "OFB".to_string(),
            CipherMode::CBC => "CBC".to_string(),
            CipherMode::CFB => "CFB".to_string(),
            CipherMode::MAC => "MAC".to_string(),
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
    fn to_string() {
        assert_eq!(CipherMode::ECB.to_string(), "ECB");
        assert_eq!(CipherMode::CTR.to_string(), "CTR");
        assert_eq!(CipherMode::CTR_ACPKM.to_string(), "CTR_ACPKM");
        assert_eq!(CipherMode::OFB.to_string(), "OFB");
        assert_eq!(CipherMode::CBC.to_string(), "CBC");
        assert_eq!(CipherMode::CFB.to_string(), "CFB");
        assert_eq!(CipherMode::MAC.to_string(), "MAC");
    }

}