pub mod magma;

// re-export the magma core
pub use magma::Magma;

// re-export the CipherOperation
pub use magma::cipher_operation::CipherOperation;

// re-export the cipher modes
pub use magma::cipher_mode::{CipherMode, ecb, ctr, ctr_acpkm, ofb, cbc, cfb, mac};
