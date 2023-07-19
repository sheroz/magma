use crate::Magma;

pub trait CipherBlock <T>{
    fn encrypt(block: T) -> T;
    fn decrypt(block: T) -> T;
}

pub trait CipherBuffer {
    fn encrypt(core: &Magma, buf: &[u8]) -> Vec<u8>;
    fn decrypt(core: &Magma, buf: &[u8]) -> Vec<u8>;
}