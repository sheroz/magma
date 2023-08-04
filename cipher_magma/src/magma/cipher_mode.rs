pub mod ecb;
pub mod ctr;
pub mod ctr_acpkm;
pub mod ofb;
pub mod cbc;
pub mod cfb;
pub mod mac;

/// **Cipher Mode**
/// 
/// [Cipher Modes](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
/// 
/// * **ECB** - Electronic Codebook Mode
/// * **CTR** - Counter Encryption Mode
/// * **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html), [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
/// * **OFB** - Output Feedback Mode
/// * **CBC** - Cipher Block Chaining Mode
/// * **CFB** - Cipher Feedback Mode
/// * **MAC** - Message Authentication Code Generation Mode
#[derive(PartialEq, Clone)]
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
