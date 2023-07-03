// setting up the openssl dependencies:
// https://docs.rs/openssl/latest/openssl/
// for Ubuntu:
// $ sudo apt-get install pkg-config libssl-dev

use openssl::sha::sha256;

pub fn sha256_digest(txt: &str) -> String {
    let hash = sha256(txt.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sha256_digest_test() {
        let txt = "Hello world!";
        let digest = super::sha256_digest(txt);
        let expected = "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a";
        assert_eq!(digest, expected);
    }
}