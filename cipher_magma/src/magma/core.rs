
use crate::*;
use crate::magma::utils;

pub struct Core {
    pub (crate) key: [u32; 8],
    pub (crate)round_keys: [u32; 32],
    pub (crate)substitution_box: [u8; 128],
}

impl Core {

    pub fn new() -> Self {
        Core {
            key: [0u32; 8],
            round_keys: [0u32; 32],
            substitution_box: SUBSTITUTION_BOX_RFC7836.clone(),
        }
    }

    /// Sets the cipher key from `[u32;8]` array
    ///
    /// # Arguments
    ///
    /// * `key` - A reference to `[u32;8]` array
    pub(super) fn set_key_u32(&mut self, key: &[u32; 8]) {
        self.key.clone_from(key);
        self.prepare_round_keys();
    }

    /// Sets the cipher key from slice of u8 bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - A `&[u8]` slice with 32 byte elements
    pub(super) fn set_key_u8(&mut self, bytes: &[u8]) {
        self.set_key_u32(&Self::key_from_u8(bytes));
    }

    fn key_from_u8(bytes: &[u8]) -> [u32;8] {
        assert!(bytes.len() == 32);
        let mut key = [0_u32;8];
        let mut array_u8 = [0u8; 4];
        for (index, chunk) in bytes.chunks(4).enumerate() {
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            key[index] = u32::from_be_bytes(array_u8);
        }
        key 
    }

    /// Prepares [round keys](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.3) from the cipher key
    fn prepare_round_keys(&mut self) {
        const ROUND_KEY_POSITION: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3,
            2, 1, 0,
        ];

        for index in 0..32 {
            let round_key_position = ROUND_KEY_POSITION[index] as usize;
            self.round_keys[index] = self.key[round_key_position];
        }
    }

    /// Sets the substitution box
    ///
    /// # Arguments
    ///
    /// * `substitution_box` - A reference to `[u8;128]` array
    pub (super) fn set_substitution_box(&mut self, substitution_box: &[u8; 128]) {
        self.substitution_box.copy_from_slice(substitution_box);
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `t: V_32 -> V_32`
    #[inline]
    fn transformation_t(&self, a: u32) -> u32 {
        let mut res: u32 = 0;
        let mut shift_count = 0;
        for i in 0..8 {
            let v = (a >> shift_count) & 0xF;
            let s = self.substitution_box[(i * 16 + v) as usize] as u32;
            res |= s << shift_count;
            shift_count += 4;
        }
        res
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `g[k]: V_32 -> V_32`
    #[inline]
    fn transformation_g(&self, k: u32, a: u32) -> u32 {
        let res = self.transformation_t(((k as u64) + (a as u64)) as u32);
        res.rotate_left(11)
    }

    /// [Transformation](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.2)
    ///
    /// `G[k]: V_32[*]V_32 -> V_32[*]V_32`
    #[inline]
    fn transformation_big_g(&self, k: u32, a_1: u32, a_0: u32) -> (u32, u32) {
        (a_0, self.transformation_g(k, a_0) ^ a_1)
    }

    /// Returns [encrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.1) as `u64` value
    ///
    /// # Arguments
    ///
    /// * `block_in` - a plaintext value as `u64`
    #[inline]
    pub fn encrypt(&self, block_in: u64) -> u64 {
        // split the input block into u32 parts
        let (mut a_1, mut a_0) = utils::u64_split(block_in);

        // crypto transformations
        let mut round = 0;
        while round < 32 {
            (a_1, a_0) = self.transformation_big_g(self.round_keys[round], a_1, a_0);
            round += 1;
        }

        // join u32 parts into u64 block
        utils::u32_join(a_0, a_1)
    }

    /// Returns [decrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.2) as `u64` value
    ///
    /// # Arguments
    ///
    /// * `block_in` - a ciphertext value as `u64`
    #[inline]
    pub fn decrypt(&self, block_in: u64) -> u64 {
        // split the input block into u32 parts
        let (mut b_1, mut b_0) = utils::u64_split(block_in);

        // crypto transformations
        let mut round = 32;
        while round != 0 {
            round -= 1;
            (b_1, b_0) = self.transformation_big_g(self.round_keys[round], b_1, b_0);
        }

        // join u32 parts into u64 block
        utils::u32_join(b_0, b_1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_initialization() {
        let core = Core::new();
        assert_eq!(core.key, [0u32; 8]);
        assert_eq!(core.round_keys, [0u32; 32]);
        assert_eq!(core.substitution_box, SUBSTITUTION_BOX_RFC7836);
    }

    #[test]
    fn set_key_u32_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let mut core = Core::new();
        core.set_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(core.key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn set_key_u8_rfc8891() {
        use crypto_vectors::gost::rfc8891;
        let mut core = Core::new();
        core.set_key_u8(&rfc8891::CIPHER_KEY_U8_ARRAY);
        assert_eq!(core.key, rfc8891::CIPHER_KEY);
    }

    #[test]
    fn round_keys_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.3

        use crypto_vectors::gost::rfc8891;
        let mut core = Core::new();
        core.set_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(core.round_keys, rfc8891::ROUND_KEYS);
    }


    #[test]
    fn transformation_t_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.1

        use crypto_vectors::gost::rfc8891;
        let t = rfc8891::TRANSFORMATION_T;

        let core = Core::new();
        assert_eq!(core.transformation_t(t[0].0), t[0].1);
        assert_eq!(core.transformation_t(t[1].0), t[1].1);
        assert_eq!(core.transformation_t(t[2].0), t[2].1);
        assert_eq!(core.transformation_t(t[3].0), t[3].1);
    }

    #[test]
    fn transformation_g_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.2

        use crypto_vectors::gost::rfc8891;
        let g = rfc8891::TRANSFORMATION_G;

        let core = Core::new();

        assert_eq!(core.transformation_g(g[0].0 .0, g[0].0 .1), g[0].1);
        assert_eq!(core.transformation_g(g[1].0 .0, g[1].0 .1), g[1].1);
        assert_eq!(core.transformation_g(g[2].0 .0, g[2].0 .1), g[2].1);
        assert_eq!(core.transformation_g(g[3].0 .0, g[3].0 .1), g[3].1);
    }

    #[test]
    fn transformation_big_g_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#section-a.4

        use crypto_vectors::gost::rfc8891;
        let big_g = rfc8891::TRANSFORMATION_BIG_G;

        let core = Core::new();
        core.set_key_u32(&rfc8891::CIPHER_KEY);

        let (mut a_1, mut a_0) = utils::u64_split(rfc8891::PLAINTEXT);

        for round in 0..32 {
            (a_1, a_0) = core.transformation_big_g(core.round_keys[round], a_1, a_0);
            assert_eq!(big_g[round], (a_1, a_0));
        }
    }

    #[test]
    fn encrypt_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-test-encryption

        use crypto_vectors::gost::rfc8891;
        let mut core = Core::new();
        core.set_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(core.encrypt(rfc8891::PLAINTEXT), rfc8891::CIPHERTEXT);
    }

    #[test]
    fn decrypt_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-test-decryption

        use crypto_vectors::gost::rfc8891;
        let mut core = Core::new();
        core.set_key_u32(&rfc8891::CIPHER_KEY);
        assert_eq!(core.decrypt(rfc8891::CIPHERTEXT), rfc8891::PLAINTEXT);
    }

    #[test]
    fn encrypt_rfc5830() {
        // Test vectors for GOST 28147-89
        // https://www.rfc-editor.org/rfc/rfc5831#section-7

        use crypto_vectors::gost::rfc5831;

        let mut core = Core::new();
        core.set_substitution_box(&SUBSTITUTION_BOX_RFC5831);

        core.set_key_u32(&rfc5831::CIPHER_KEY1);
        assert_eq!(core.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT1);

        core.set_key_u32(&rfc5831::CIPHER_KEY2);
        assert_eq!(core.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT2);

        core.set_key_u32(&rfc5831::CIPHER_KEY3);
        assert_eq!(core.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT3);

        core.set_key_u32(&rfc5831::CIPHER_KEY4);
        assert_eq!(core.encrypt(rfc5831::PLAINTEXT), rfc5831::CIPHERTEXT4);
    }

    #[test]
    fn decrypt_rfc5830() {
        // Test vectors for GOST 28147-89
        // https://www.rfc-editor.org/rfc/rfc5831#section-7

        use crypto_vectors::gost::rfc5831;

        let mut core = Core::new();
        core.set_substitution_box(&SUBSTITUTION_BOX_RFC5831);

        core.set_key_u32(&rfc5831::CIPHER_KEY1);
        assert_eq!(core.decrypt(rfc5831::CIPHERTEXT1), rfc5831::PLAINTEXT);

        core.set_key_u32(&rfc5831::CIPHER_KEY2);
        assert_eq!(core.decrypt(rfc5831::CIPHERTEXT2), rfc5831::PLAINTEXT);

        core.set_key_u32(&rfc5831::CIPHER_KEY3);
        assert_eq!(core.decrypt(rfc5831::CIPHERTEXT3), rfc5831::PLAINTEXT);

        core.set_key_u32(&rfc5831::CIPHER_KEY4);
        assert_eq!(core.decrypt(rfc5831::CIPHERTEXT4), rfc5831::PLAINTEXT);
    }

    #[test]
    fn encrypt_gost_r_34_13_2015_ecb() {
        use crypto_vectors::gost::r3413_2015;

        let mut core = Core::new();
        core.set_key_u32(&r3413_2015::CIPHER_KEY);
        assert_eq!(
            core.encrypt(r3413_2015::PLAINTEXT1),
            r3413_2015::CIPHERTEXT1_ECB
        );
        assert_eq!(
            core.encrypt(r3413_2015::PLAINTEXT2),
            r3413_2015::CIPHERTEXT2_ECB
        );
        assert_eq!(
            core.encrypt(r3413_2015::PLAINTEXT3),
            r3413_2015::CIPHERTEXT3_ECB
        );
        assert_eq!(
            core.encrypt(r3413_2015::PLAINTEXT4),
            r3413_2015::CIPHERTEXT4_ECB
        );
    }

    #[test]
    fn decrypt_gost_r_34_13_2015_ecb() {
        use crypto_vectors::gost::r3413_2015;

        let mut core = Core::new();
        core.set_key_u32(&r3413_2015::CIPHER_KEY);

        assert_eq!(
            core.decrypt(r3413_2015::CIPHERTEXT1_ECB),
            r3413_2015::PLAINTEXT1
        );
        assert_eq!(
            core.decrypt(r3413_2015::CIPHERTEXT2_ECB),
            r3413_2015::PLAINTEXT2
        );
        assert_eq!(
            core.decrypt(r3413_2015::CIPHERTEXT3_ECB),
            r3413_2015::PLAINTEXT3
        );
        assert_eq!(
            core.decrypt(r3413_2015::CIPHERTEXT4_ECB),
            r3413_2015::PLAINTEXT4
        );
    }

}