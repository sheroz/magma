//! Cipher operation
#[derive(PartialEq, Clone)]
pub enum CipherOperation {
    /// Encrypting operation
    Encrypt,

    /// Decrypting operation
    Decrypt,

    /// Message Authentication Code (MAC) Generation
    MessageAuthentication
}
