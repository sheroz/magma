/// Block encryption sample
pub fn sample_encrypt_block() {
    use cipher_magma::Magma;

    let key: [u32; 8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
        0xfcfdfeff,
    ];
    println!("Key:\n{:x?}\n", key);
    let magma = Magma::with_key(key);

    let source = 0xfedcba9876543210_u64;
    println!("Source:\n{:x}\n", source);

    let encrypted = magma.encrypt(source);
    println!("Encrypted:\n{:x}\n", encrypted);

    let decrypted = magma.decrypt(encrypted);
    println!("Decrypted:\n{:x}", decrypted);

    assert_eq!(decrypted, source);
}
