use crate::Magma;

pub trait CipherBlock {
    fn encrypt(block: u64) -> u64;
    fn decrypt(block: u64) -> u64;
}

pub trait CipherBuffer {
    fn encrypt(core: &Magma, buf: &[u8]) -> Vec<u8>;
    fn decrypt(core: &Magma, buf: &[u8]) -> Vec<u8>;
}