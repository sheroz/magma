#[cfg(test)]
mod tests {
    use num::BigInt;

    #[test]
    fn sample_bigint_test() {
        let a = BigInt::from(2);
        let r = a.pow(3);
        assert_eq!(r, BigInt::from(8));
    }
}