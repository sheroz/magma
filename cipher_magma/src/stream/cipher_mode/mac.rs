//! Implements Message Authentication Code (MAC)

use crate::{MagmaStream, CipherOperation, CipherMode};
use crate::core::utils;

/// Returns the Message Authentication Code (MAC)
///
/// # Arguments
/// * core - a mutable reference to `Magma`
/// * msg_buf - a slice of `&[u8]` data to feed
///
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
///
/// Page 26, Section 5.6
pub fn calculate(magma: &mut MagmaStream, msg_buf: &[u8]) -> u32 {
    magma.reset_feedback();
    magma.update_context(CipherOperation::MessageAuthentication, CipherMode::MAC);

    update(magma, msg_buf);
    finalize(magma)
}

/// Updates the context of Message Authentication Code (MAC)
///
/// # Arguments
/// * core - a mutable reference to `Magma`
/// * msg_buf - a slice of `&[u8]` data to feed
///
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
///
/// Page 26, Section 5.6
pub fn update(magma: &mut MagmaStream, msg_buf: &[u8]) {
    magma.update_context(CipherOperation::MessageAuthentication, CipherMode::MAC);

    let mut feedback_chained = magma.context.feedback.block.is_some();
    let mut feedback = if feedback_chained {
        magma.context.feedback.block.unwrap()
    } else {
        0
    };

    let mut chunks = msg_buf.chunks(8);
    while let Some(chunk) = chunks.next() {
        let mut array_u8 = [0u8; 8];
        chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);

        let chunk_len = chunk.len();
        if chunk_len < 8 {
            // Uncomplete chunk, needs padding
            // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
            // Page 11, Section 4.1.3
            // Padding the remaining bytes:
            // 1. Mark the starting byte with 0x80
            // 2. Other bytes already padded with 0x00
            array_u8[chunk_len] = 0x80_u8;
            magma.context.padded = true;
        }

        let block_in = u64::from_be_bytes(array_u8);

        feedback = block_in
            ^ if feedback_chained {
                magma.core.encrypt(feedback)
            } else {
                feedback
            };

        feedback_chained = true;
    }

    // update the feedback state
    magma.context.feedback.block = Some(feedback);
}

/// Finalizes the current context and returns the Message Authentication Code (MAC)
///
/// # Arguments
/// * core - a mutable reference to `Magma`
///
/// [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
///
/// Page 26, Section 5.6
pub fn finalize(magma: &mut MagmaStream) -> u32 {
    magma.update_context(CipherOperation::MessageAuthentication, CipherMode::MAC);

    let (k1, k2) = generate_cmac_subkeys(magma);
    let k_n = if magma.context.padded { k2 } else { k1 };

    let finalizer = match magma.context.feedback.block {
        Some(finalizer) => finalizer ^ k_n,
        None => panic!("Context not found, please use update() before finalizing."),
    };

    let final_block = magma.core.encrypt(finalizer);
    let (mac, _) = utils::u64_split(final_block);

    magma.reset_context();
    mac
}

/// Returns subkeys for CMAC as `(u64, u64)`
///
/// Key generation algorithm is based on:
///
/// [OMAC1 a.k.a CMAC](https://en.wikipedia.org/wiki/One-key_MAC)
fn generate_cmac_subkeys(magma: &mut MagmaStream) -> (u64, u64) {
    let r = magma.core.encrypt(0x0_u64);

    let b64 = 0x1b_u64;
    let mcb_u64 = 0x80000000_00000000_u64;

    let k1 = if (r & mcb_u64) == 0 {
        r << 1
    } else {
        (r << 1) ^ b64
    };

    let k2 = if (k1 & mcb_u64) == 0 {
        k1 << 1
    } else {
        (k1 << 1) ^ b64
    };

    (k1, k2)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn cmac_subkeys_gost_r_34_13_2015() {
        use crypto_vectors::gost::r3413_2015;
        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::MAC);
        let (k1, k2) = generate_cmac_subkeys(&mut magma);
        assert_eq!(k1, 0x5f459b3342521424_u64);
        assert_eq!(k2, 0xbe8b366684a42848_u64);
    }

    #[test]
    fn mac_steps_gost_r_34_13_2015() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 40, Section A.2.6

        use crypto_vectors::gost::r3413_2015;
        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::MAC);

        let (k1, k2) = generate_cmac_subkeys(&mut magma);
        assert_eq!(k1, 0x5f459b3342521424_u64);
        assert_eq!(k2, 0xbe8b366684a42848_u64);

        let k_n = k1;

        let i1 = r3413_2015::PLAINTEXT1;
        let o1 = magma.core.encrypt(i1);
        assert_eq!(o1, 0x2b073f0494f372a0_u64);

        let i2 = o1 ^ r3413_2015::PLAINTEXT2;
        assert_eq!(i2, 0xf053f8006cebef80_u64);
        let o2 = magma.core.encrypt(i2);
        assert_eq!(o2, 0xc89ed814fd5e18e9_u64);

        let i3 = o2 ^ r3413_2015::PLAINTEXT3;
        assert_eq!(i3, 0x8206233a9af61aa5_u64);
        let o3 = magma.core.encrypt(i3);
        assert_eq!(o3, 0xf739b18d34289b00_u64);

        let i4 = o3 ^ r3413_2015::PLAINTEXT4 ^ k_n;
        assert_eq!(i4, 0x216e6a2561cff165_u64);
        let o4 = magma.core.encrypt(i4);
        assert_eq!(o4, 0x154e72102030c5bb_u64);

        let (mac, _) = utils::u64_split(o4);
        assert_eq!(mac, r3413_2015::MAC);
    }

    #[test]
    fn mac_update_1x256bytes() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 40, Section A.2.6

        use crypto_vectors::gost::r3413_2015;

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::MAC);

        update(&mut magma, &source);
        let mac = finalize(&mut magma);
        assert_eq!(mac, r3413_2015::MAC);
    }

    #[test]
    fn mac_update_4x8bytes() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 40, Section A.2.6

        use crypto_vectors::gost::r3413_2015;

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::MAC);

        update(&mut magma, &r3413_2015::PLAINTEXT1.to_be_bytes());
        update(&mut magma, &r3413_2015::PLAINTEXT2.to_be_bytes());
        update(&mut magma, &r3413_2015::PLAINTEXT3.to_be_bytes());
        update(&mut magma, &r3413_2015::PLAINTEXT4.to_be_bytes());

        let mac = finalize(&mut magma);
        assert_eq!(mac, r3413_2015::MAC);
    }

    #[test]
    fn mac_calculate() {
        // Test vectors GOST R 34.13-2015
        // https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf
        // Page 40, Section A.2.6

        use crypto_vectors::gost::r3413_2015;

        let mut magma = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::MAC);

        let mut source = Vec::<u8>::new();
        source.extend_from_slice(&r3413_2015::PLAINTEXT1.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT2.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT3.to_be_bytes());
        source.extend_from_slice(&r3413_2015::PLAINTEXT4.to_be_bytes());

        let mac = calculate(&mut magma, &source);
        assert_eq!(mac, r3413_2015::MAC);
    }

    #[test]
    #[should_panic]
    fn mac_finilize_no_context() {
        use crypto_vectors::gost::r3413_2015;
        let mut magma_stream = MagmaStream::new(r3413_2015::CIPHER_KEY.clone(), CipherMode::MAC);
        finalize(&mut magma_stream);
    }
}
