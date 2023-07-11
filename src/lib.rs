//! **Block Cipher "Magma"**
//! 
//! Implemented and tested according to specifications:
//! 1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015
//! 2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89

/// Block Cipher "Magma"
pub struct Magma {
    cipher_key: [u32;8],
    round_keys: [u32;32],
    substitution_box: [u8;128]
}

/// Cipher mode
/// 
/// Only **ECB** mode is currently implemented.
/// 
/// **CTR**, **CFB**, **MAC** modes **are not implemented** yet.
/// 
/// [Cipher Modes](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf)

/*
    RFC 5831: GOST R 34.11-94
    hash function:
    https://datatracker.ietf.org/doc/rfc5831/
    https://datatracker.ietf.org/doc/html/rfc4357
    https://en.wikipedia.org/wiki/GOST_(hash_function)

    GOST R 34.11-94
    GOST 34.311-95
    GOST hash function
    GOST 28147-89 IMIT
*/

pub enum CipherMode {
    /// Electronic Codebook Mode
    ECB, 

    /*
    /// Counter Encryption Mode
    CTR, 
    /// Output Feedback
    OFB,
    ///Cipher Block Chaining
    СВС
    /// CipherFeedback Mode
    CFB,
    /// Message Authentication Code 
    MAC, 
    */
}

impl Magma {

    /// Substitution Box (S-Box) data according to [Appendix C. RFC7836](https://datatracker.ietf.org/doc/html/rfc7836#appendix-C)
    /// 
    /// Parameter set: id-tc26-gost-28147-param-Z
    pub const SUBSTITUTION_BOX_RFC7836: [u8;128] = [
        0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9, 0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1,
        0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC, 0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF,
        0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD, 0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0,
        0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6, 0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB,
        0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD, 0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC,
        0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA, 0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0,
        0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC, 0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7,
        0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3, 0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2,
    ];

    /// Substitution Box (S-Box) data according to [RFC5831](https://datatracker.ietf.org/doc/html/rfc5831#section-7.1)
    /// 
    /// As per [Appendix B of RFC8891](https://datatracker.ietf.org/doc/html/rfc8891.html#section-appendix.b) data values converted
    /// from little-endian to big-endian format.
    /// 
    /// OID: 1.2.643.2.2.30.0
    pub const SUBSTITUTION_BOX_RFC5831: [u8;128] = [
        0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3,
        0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
        0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB,
        0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3,
        0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2,
        0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
        0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
        0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC,
    ];

    /// Returns a new Magma by using RFC7836 based substitution box
    ///
    /// # Example
    /// ```
    /// use cipher_magma::Magma;
    /// let magma = Magma::new();
    /// ```
    pub fn new() -> Magma {
        let cipher_key = [0u32;8];
        let round_keys = [0u32;32];
        let substitution_box = Magma::SUBSTITUTION_BOX_RFC7836.clone();
        Magma { cipher_key, round_keys, substitution_box }
    }

    /// Returns a new Magma, initialized with cipher key
    /// and using RFC7836 based substitution box
    /// 
    /// # Arguments
    ///
    /// * `cipher_key` - A reference to `[u32;8]` array
    ///
    /// # Example
    /// ```
    /// use cipher_magma::Magma;
    /// let cipher_key: [u32;8] = [
    ///     0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ///     ];
    /// 
    /// let magma = Magma::new_with_key(&cipher_key);
    /// ```
    pub fn new_with_key(cipher_key: &[u32;8]) -> Magma {
        let mut engine = Magma::new();
        engine.set_key(cipher_key);
        engine
    }

    /// Sets the substitution box
    /// 
    /// # Arguments
    ///
    /// * `substitution_box` - A reference to `[u8;128]` array
    pub fn set_substitution_box(&mut self, substitution_box: &[u8;128]) {
        self.substitution_box.copy_from_slice(substitution_box);
    }

    /// Sets the cipher key from `[u32;8]` array
    /// 
    /// # Arguments
    ///
    /// * `cipher_key` - A reference to `[u32;8]` array
    pub fn set_key(&mut self, cipher_key: &[u32;8]) {
        self.cipher_key.clone_from(cipher_key);
        self.prepare_round_keys();
    }

    /// Sets the cipher key from slice of u8 bytes
    /// 
    /// # Arguments
    ///
    /// * `cipher_key_bytes` - A `&[u8]` slice
    pub fn set_key_from_bytes(&mut self, cipher_key_bytes: &[u8]) {
        assert!(cipher_key_bytes.len() == 32);

        let mut array_u8 = [0u8;4];
        for (index, chunk) in cipher_key_bytes.chunks(4).enumerate() {
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            self.cipher_key[index] = u32::from_be_bytes(array_u8);
        }

        self.prepare_round_keys();
    }

    /// Prepares [round keys](https://datatracker.ietf.org/doc/html/rfc8891.html#section-4.3) from the cipher key
    fn prepare_round_keys(&mut self) {
        const ROUND_KEY_POSITION: [u8;32] = [
            0, 1, 2, 3, 4, 5, 6, 7,
            0, 1, 2, 3, 4, 5, 6, 7,
            0, 1, 2, 3, 4, 5, 6, 7,
            7, 6, 5, 4, 3, 2, 1, 0
        ];
    
        for index in 0..32 {
            let round_key_position = ROUND_KEY_POSITION[index] as usize;
            self.round_keys[index]= self.cipher_key[round_key_position];
        }
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

    #[inline]
    fn u64_split(a: u64) -> (u32, u32) {
        ((a >> 32) as u32, a  as u32)
    } 

    #[inline]
    fn u64_join(a_1: u32, a_0: u32) -> u64 {
        ((a_0 as u64) << 32) | (a_1 as u64)
    } 

    /// Returns [encrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.1) as `u64` value
    /// 
    /// # Arguments
    ///
    /// * `block_u64` - A `u64` value 
    pub fn encrypt(&self, block_u64: u64) -> u64 {
        // split the input block into u32 parts
        let (mut a_1, mut a_0) = Magma::u64_split(block_u64);

        // crypto transformations
        let mut round = 0;
        while round < 32 {
            (a_1, a_0) = self.transformation_big_g(self.round_keys[round], a_1, a_0); 
            round += 1;
        }

        // join u32 parts into u64 block
        Magma::u64_join(a_1, a_0)
    }
    
    /// Returns [decrypted block](https://datatracker.ietf.org/doc/html/rfc8891.html#section-5.2) as `u64` value
    /// 
    /// # Arguments
    ///
    /// * `block_u64` - A `u64` value 
    pub fn decrypt(&self, block_u64: u64) -> u64 {
        // split the input block into u32 parts
        let (mut b_1, mut b_0) = Magma::u64_split(block_u64);

        // crypto transformations
        let mut round = 32;
        while round != 0 {
            round -= 1;
            (b_1, b_0) = self.transformation_big_g(self.round_keys[round], b_1, b_0);
        }

        // join u32 parts into u64 block
        Magma::u64_join(b_1, b_0)
    }

    /// Returns encrypted buffer as `Vec<u8>`
    /// 
    /// # Arguments
    ///
    /// * `buf` - A plaintext as `&[u8]` slice
    /// * `cipher_mode` - encryption mode as defined in `CipherMode`
    pub fn encrypt_buffer(&mut self, buf: &[u8], cipher_mode: CipherMode) -> Vec<u8> {
        match cipher_mode {
            CipherMode::ECB => self.process_buffer_ecb(buf, Magma::encrypt),
        }
    }
    
    /// Returns decrypted buffer as `Vec<u8>`
    /// 
    /// # Arguments
    ///
    /// * `buf` - A ciphertext as `&[u8]` slice
    /// * `cipher_mode` - decryption mode as defined in `CipherMode`
    pub fn decrypt_buffer(&mut self, buf: &[u8], cipher_mode: CipherMode) -> Vec<u8> {
        match cipher_mode {
            CipherMode::ECB => self.process_buffer_ecb(buf, Magma::decrypt),
        }
    }

    fn process_buffer_ecb(&mut self, src_buf: &[u8], m_invoke: fn(&Magma, u64) -> u64) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(src_buf.len());
        for chunk in src_buf.chunks(8) {
            let mut array_u8 = [0u8;8];
            chunk.iter().enumerate().for_each(|t| array_u8[t.0] = *t.1);
            let block_u64 = u64::from_be_bytes(array_u8);
            let result_u64 = m_invoke(&self, block_u64);
            result.extend_from_slice(&result_u64.to_be_bytes());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors RFC8891:
    // https://datatracker.ietf.org/doc/html/rfc8891.html#name-key-schedule-2

    const CIPHER_KEY_RFC8891: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    const PLAINTEXT_RFC8891: u64 = 0xfedcba9876543210_u64;
    const ENCRYPTED_RFC8891: u64 = 0x4ee901e5c2d8ca3d_u64;

    #[test]
    fn default_initialization() {
        let magma = Magma::new();
        assert_eq!(magma.cipher_key, [0u32;8]);
        assert_eq!(magma.round_keys, [0u32;32]);
        assert_eq!(magma.substitution_box, Magma::SUBSTITUTION_BOX_RFC7836);
    }

    #[test]
    fn initialize_with_key_rfc8891() {
        let magma = Magma::new_with_key(&CIPHER_KEY_RFC8891);
        assert_eq!(magma.cipher_key, CIPHER_KEY_RFC8891);
    }

    #[test]
    fn set_key_rfc8891() {
        let mut magma = Magma::new();
        magma.set_key(&CIPHER_KEY_RFC8891);
        assert_eq!(magma.cipher_key, CIPHER_KEY_RFC8891);
    }

    #[test]
    fn set_keys_from_big_endian_u8_array_rfc8891() {
        let cipher_key_u8: [u8;32] = [
             0xff, 0xee, 0xdd, 0xcc, 
             0xbb, 0xaa, 0x99, 0x88, 
             0x77, 0x66, 0x55, 0x44, 
             0x33, 0x22, 0x11, 0x00, 
             0xf0, 0xf1, 0xf2, 0xf3, 
             0xf4, 0xf5, 0xf6, 0xf7, 
             0xf8, 0xf9, 0xfa, 0xfb, 
             0xfc, 0xfd, 0xfe, 0xff, 
            ];

        let mut magma = Magma::new();
        magma.set_key_from_bytes(&cipher_key_u8);
        assert_eq!(magma.cipher_key, CIPHER_KEY_RFC8891);
    }

    #[test]
    fn round_keys_rfc8891() {
        let magma = Magma::new_with_key(&CIPHER_KEY_RFC8891);

        let round_keys: [u32;32]= [
            0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
            0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
            0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
            0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3, 0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc
        ];

        assert_eq!(magma.round_keys, round_keys);
    }

    #[test]
    fn transformation_t_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-key-schedule-2

        let magma = Magma::new();

        assert_eq!(magma.transformation_t(0xfdb97531), 0x2a196f34);
        assert_eq!(magma.transformation_t(0x2a196f34), 0xebd9f03a);
        assert_eq!(magma.transformation_t(0xebd9f03a), 0xb039bb3d);
        assert_eq!(magma.transformation_t(0xb039bb3d), 0x68695433);
    }

    #[test]
    fn transformation_g_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-key-schedule-2

        let magma = Magma::new();

        assert_eq!(magma.transformation_g(0x87654321, 0xfedcba98), 0xfdcbc20c);
        assert_eq!(magma.transformation_g(0xfdcbc20c, 0x87654321), 0x7e791a4b);
        assert_eq!(magma.transformation_g(0x7e791a4b, 0xfdcbc20c), 0xc76549ec);
        assert_eq!(magma.transformation_g(0xc76549ec, 0x7e791a4b), 0x9791c849);
    }

    #[test]
    fn split_into_u32_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-key-schedule-2
        assert_eq!(Magma::u64_split(0xfedcba9876543210_u64),(0xfedcba98_u32, 0x76543210_u32));
    }

    #[test]
    fn join_as_u64_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-key-schedule-2
        assert_eq!(Magma::u64_join(0xc2d8ca3d_u32, 0x4ee901e5_u32), 0x4ee901e5c2d8ca3d_u64);
    }

    #[test]
    fn transformation_big_g_rfc8891() {
        // Test vectors RFC8891:
        // https://datatracker.ietf.org/doc/html/rfc8891.html#name-key-schedule-2

        let magma = Magma::new_with_key(&CIPHER_KEY_RFC8891);

        let (mut a_1, mut a_0) = (0xfedcba98_u32, 0x76543210_u32);
        let expected = [
            (0x76543210_u32, 0x28da3b14_u32),
            (0x28da3b14_u32, 0xb14337a5_u32),
            (0xb14337a5_u32, 0x633a7c68_u32),
            (0x633a7c68_u32, 0xea89c02c_u32),
            (0xea89c02c_u32, 0x11fe726d_u32),
            (0x11fe726d_u32, 0xad0310a4_u32),
            (0xad0310a4_u32, 0x37d97f25_u32),
            (0x37d97f25_u32, 0x46324615_u32),
            (0x46324615_u32, 0xce995f2a_u32),
            (0xce995f2a_u32, 0x93c1f449_u32),
            (0x93c1f449_u32, 0x4811c7ad_u32),
            (0x4811c7ad_u32, 0xc4b3edca_u32),
            (0xc4b3edca_u32, 0x44ca5ce1_u32),
            (0x44ca5ce1_u32, 0xfef51b68_u32),
            (0xfef51b68_u32, 0x2098cd86_u32),
            (0x2098cd86_u32, 0x4f15b0bb_u32),
            (0x4f15b0bb_u32, 0xe32805bc_u32),
            (0xe32805bc_u32, 0xe7116722_u32),
            (0xe7116722_u32, 0x89cadf21_u32),
            (0x89cadf21_u32, 0xbac8444d_u32),
            (0xbac8444d_u32, 0x11263a21_u32),
            (0x11263a21_u32, 0x625434c3_u32),
            (0x625434c3_u32, 0x8025c0a5_u32),
            (0x8025c0a5_u32, 0xb0d66514_u32),
            (0xb0d66514_u32, 0x47b1d5f4_u32),
            (0x47b1d5f4_u32, 0xc78e6d50_u32),
            (0xc78e6d50_u32, 0x80251e99_u32),
            (0x80251e99_u32, 0x2b96eca6_u32),
            (0x2b96eca6_u32, 0x05ef4401_u32),
            (0x05ef4401_u32, 0x239a4577_u32),
            (0x239a4577_u32, 0xc2d8ca3d_u32),
            (0xc2d8ca3d_u32, 0x4ee901e5_u32)
        ];

        for round in 0..32 {
            (a_1, a_0) = magma.transformation_big_g(magma.round_keys[round], a_1, a_0); 
            assert_eq!(expected[round], (a_1, a_0));
        }
    }

    #[test]
    fn encrypt_rfc8891() {
        let magma = Magma::new_with_key(&CIPHER_KEY_RFC8891);
        assert_eq!(magma.encrypt(PLAINTEXT_RFC8891), ENCRYPTED_RFC8891);
    }

    #[test]
    fn decrypt_rfc8891() {
        let magma = Magma::new_with_key(&CIPHER_KEY_RFC8891);
        assert_eq!(magma.decrypt(ENCRYPTED_RFC8891), PLAINTEXT_RFC8891);
    }

    #[test]
    fn encrypt_rfc5830() {
        /*
            Test vectors for GOST 28147-89
            https://www.rfc-editor.org/rfc/rfc5831#section-7

            K1 (little-endian) = 0x733D2C20 0x65686573 0x74746769 0x79676120 0x626E7373 0x20657369 0x326C6568 0x33206D54
            K1 = [0x33206D54, 0x326C6568, 0x20657369, 0x626E7373, 0x79676120, 0x74746769, 0x65686573, 0x733D2C20]    

            K2 (little-endian) = 0x110C733D 0x0D166568 0x130E7474 0x06417967 0x1D00626E 0x161A2065 0x090D326C 0x4D393320
            K2 = [0x4D393320, 0x090D326C, 0x161A2065, 0x1D00626E, 0x06417967, 0x130E7474, 0x0D166568, 0x110C733D]    

            K3 (little-endian) = 0x80B111F3 0x730DF216 0x850013F1 0xC7E1F941 0x620C1DFF 0x3ABAE91A 0x3FA109F2 0xF513B239
            k3 = [0xF513B239, 0x3FA109F2, 0x3ABAE91A, 0x620C1DFF, 0xC7E1F941, 0x850013F1, 0x730DF216, 0x80B111F3]

            K4 (little-endian) = 0xA0E2804E 0xFF1B73F2 0xECE27A00 0xE7B8C7E1 0xEE1D620C 0xAC0CC5BA 0xA804C05E 0xA18B0AEC
            k4 = [0xA18B0AEC, 0xA804C05E, 0xAC0CC5BA, 0xEE1D620C, 0xE7B8C7E1, 0xECE27A00, 0xFF1B73F2, 0xA0E2804E]

            Outputs:
            S1 = 0x42ABBCCE 0x32BC0B1B
            S2 = 0x5203EBC8 0x5D9BCFFD
            S3 = 0x8D345899 0x00FF0E28
            S4 = 0xE7860419 0x0D2A562D
        */

        let k1: [u32;8] = [0x33206D54, 0x326C6568, 0x20657369, 0x626E7373, 0x79676120, 0x74746769, 0x65686573, 0x733D2C20];
        let k2: [u32;8] = [0x4D393320, 0x090D326C, 0x161A2065, 0x1D00626E, 0x06417967, 0x130E7474, 0x0D166568, 0x110C733D];    
        let k3: [u32;8] = [0xF513B239, 0x3FA109F2, 0x3ABAE91A, 0x620C1DFF, 0xC7E1F941, 0x850013F1, 0x730DF216, 0x80B111F3];
        let k4: [u32;8] = [0xA18B0AEC, 0xA804C05E, 0xAC0CC5BA, 0xEE1D620C, 0xE7B8C7E1, 0xECE27A00, 0xFF1B73F2, 0xA0E2804E];

        let s1 = 0x42ABBCCE32BC0B1B_u64;
        let s2 = 0x5203EBC85D9BCFFD_u64;
        let s3 = 0x8D34589900FF0E28_u64;
        let s4 = 0xE78604190D2A562D_u64;

        let plaintext = 0x0_u64;
        let mut magma = Magma::new();
        magma.set_substitution_box(&Magma::SUBSTITUTION_BOX_RFC5831);

        magma.set_key(&k1);
        assert_eq!(magma.encrypt(plaintext), s1);

        magma.set_key(&k2);
        assert_eq!(magma.encrypt(plaintext), s2);

        magma.set_key(&k3);
        assert_eq!(magma.encrypt(plaintext), s3);

        magma.set_key(&k4);
        assert_eq!(magma.encrypt(plaintext), s4);
    }

    #[test]
    fn decrypt_rfc5830() {
        // Test vectors for GOST 28147-89
        // https://www.rfc-editor.org/rfc/rfc5831#section-7

        let k1: [u32;8] = [0x33206D54, 0x326C6568, 0x20657369, 0x626E7373, 0x79676120, 0x74746769, 0x65686573, 0x733D2C20];
        let k2: [u32;8] = [0x4D393320, 0x090D326C, 0x161A2065, 0x1D00626E, 0x06417967, 0x130E7474, 0x0D166568, 0x110C733D];    
        let k3: [u32;8] = [0xF513B239, 0x3FA109F2, 0x3ABAE91A, 0x620C1DFF, 0xC7E1F941, 0x850013F1, 0x730DF216, 0x80B111F3];
        let k4: [u32;8] = [0xA18B0AEC, 0xA804C05E, 0xAC0CC5BA, 0xEE1D620C, 0xE7B8C7E1, 0xECE27A00, 0xFF1B73F2, 0xA0E2804E];

        let s1 = 0x42ABBCCE32BC0B1B_u64;
        let s2 = 0x5203EBC85D9BCFFD_u64;
        let s3 = 0x8D34589900FF0E28_u64;
        let s4 = 0xE78604190D2A562D_u64;

        let plaintext = 0x0_u64;
        let mut magma = Magma::new();
        magma.set_substitution_box(&Magma::SUBSTITUTION_BOX_RFC5831);

        magma.set_key(&k1);
        assert_eq!(magma.decrypt(s1), plaintext);

        magma.set_key(&k2);
        assert_eq!(magma.decrypt(s2), plaintext);

        magma.set_key(&k3);
        assert_eq!(magma.decrypt(s3), plaintext);

        magma.set_key(&k4);
        assert_eq!(magma.decrypt(s4), plaintext);
    }

    #[test]
    fn encrypt_decrypt_buffer_ecb() {
        let txt = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
            Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
            Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
            Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
            Quisque iaculis est et est volutpat posuere.";

        let txt_bytes = txt.as_bytes();

        let mut magma = Magma::new_with_key(&CIPHER_KEY_RFC8891);
        let encrypted = magma.encrypt_buffer(txt_bytes, CipherMode::ECB);
        assert!(!encrypted.is_empty());

        let mut decrypted = magma.decrypt_buffer(&encrypted, CipherMode::ECB);
        assert!(decrypted.len() >= encrypted.len());

        // remove padding bytes
        decrypted.truncate(txt_bytes.len());

        let decrypted_text = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_text, txt);
    }
}
