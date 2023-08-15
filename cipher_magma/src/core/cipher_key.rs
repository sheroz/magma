/// Passing cipher keys in a polymorphic way
pub enum CipherKey {
    ArrayU8([u8; 32]),
    ArrayU32([u32; 8]),
}

impl From<[u8; 32]> for CipherKey {
    /// builds key from '[u8;32]' array
    fn from(array_u8: [u8; 32]) -> Self {
        Self::ArrayU8(array_u8)
    }
}

impl From<[u32; 8]> for CipherKey {
    /// builds key from '[u32;8]' array
    fn from(array_u32: [u32; 8]) -> Self {
        Self::ArrayU32(array_u32)
    }
}
