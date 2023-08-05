//! Block Cipher "Magma"
//!
//! Implemented and tested according to specifications:
//! 1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a **GOST R 34.12-2015**
//! 2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a **GOST 28147-89**
//! 3. Block Cipher Modes: [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
//!
//! [Cipher Modes](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
//! * **ECB** - Electronic Codebook Mode
//! * **CTR** - Counter Encryption Mode
//! * **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html), [P 1323565.1.017— 2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)
//! * **OFB** - Output Feedback Mode
//! * **CBC** - Cipher Block Chaining Mode
//! * **CFB** - Cipher Feedback Mode
//! * **MAC** - Message Authentication Code Generation Mode

pub mod magma;

// re-export the magma core
pub use magma::Magma;

// re-export the CipherOperation
pub use magma::cipher_operation::CipherOperation;

// re-export the cipher modes
pub use magma::cipher_mode::{CipherMode, ecb, ctr, ctr_acpkm, ofb, cbc, cfb, mac};
