use crypto::magma;

fn main() {
    let mut gost = magma::CryptoEngine::new();

    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    gost.set_key(&cipher_key);

    let source = 0xfedcba9876543210_u64;
    println!("Source: {:x}", source);

    let encrypted = gost.encrypt(source);
    println!("Encrypted ciphertext: {:x}", encrypted);

    let decrypted = gost.decrypt(encrypted);
    println!("Decrypted source: {:x}", decrypted);
}