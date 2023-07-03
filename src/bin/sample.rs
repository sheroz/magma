fn main() {
    let txt = "Hello world!";
    let hex_encoded = crypto::openssl_sample::sha256_digest(txt);    
    println!("\nOpenSSL: SHA256 hash for {}\n{}\n", txt, hex_encoded);
}