/// Returns splitted into `(u32, u32)` result
/// 
/// # Argument 
/// 
/// * v - as `u64` value
#[inline]
pub fn u64_split(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v  as u32)
} 

/// Returns joined 'u64' result
/// 
/// # Argument 
/// 
/// * a - `u32` value to join 
/// * b - `u32` value to join
#[inline]
pub fn u32_join(a: u32, b: u32) -> u64 {
    ((a as u64) << 32) | (b as u64)
} 

#[cfg(test)]
mod tests {
    #[test]
    fn u64_split() {
        use crypto_vectors::gost::rfc8891;
        assert_eq!(super::u64_split(rfc8891::PLAINTEXT),(0xfedcba98, 0x76543210));
    }

    #[test]
    fn u32_join() {
        use crypto_vectors::gost::rfc8891;
        assert_eq!(super::u32_join(0x4ee901e5, 0xc2d8ca3d), rfc8891::CIPHERTEXT);
    }
}