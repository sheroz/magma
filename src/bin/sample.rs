use openssl::sha::sha256;

fn main() {
    let txt = "Hello world!";
    let hash = sha256(txt.as_bytes());
    let digest = hex::encode(hash);    
    assert_eq!(digest, "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a");
    println!("\nOpenSSL: SHA256 hash for {}\n{}\n", txt, digest);
}