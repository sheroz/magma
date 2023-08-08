pub enum CipherKey {
    ArrayU8([u8;32]),
    ArrayU32([u32;8]),
}

impl From<[u8;32]> for CipherKey {
    fn from(array_u8: [u8;32]) -> Self {
        Self::ArrayU8(array_u8)
    }
}

impl From<[u32;8]> for CipherKey {
    fn from(array_u32: [u32;8]) -> Self {
        Self::ArrayU32(array_u32)
    }
}
