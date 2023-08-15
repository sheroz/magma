//! Cipher operation
#[derive(PartialEq, Clone, Copy)]
pub enum CipherOperation {
    /// Encrypting operation
    Encrypt,

    /// Decrypting operation
    Decrypt,

    /// Message Authentication Code (MAC) Generation
    MessageAuthentication
}
