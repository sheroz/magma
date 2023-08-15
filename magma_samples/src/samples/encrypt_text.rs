/// Text encryption sample
pub fn sample_encrypt_text() {
    use cipher_magma::{CipherMode, MagmaStream};

    let key = [0xab; 32];
    println!("Key:\n{:x?}\n", key);
    let mut magma = MagmaStream::new(key, CipherMode::CFB);

    let source = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.";

    println!("Source:\n{}\n", String::from_utf8(source.to_vec()).unwrap());

    let encrypted = magma.encrypt(source);
    println!("Encrypted:\n{:02x?}\n", encrypted);

    let mut decrypted = magma.decrypt(&encrypted);

    if magma.get_mode().has_padding() {
        // remove padding bytes
        decrypted.truncate(source.len());
    }

    assert_eq!(decrypted, source);
    println!("Decrypted:\n{}\n", String::from_utf8(decrypted).unwrap());
}
