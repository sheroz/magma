/// Sample of encryption of large data in chunks
pub fn sample_encrypt_large_buffer() {
    use cipher_magma::{CipherMode, MagmaMode};

    const BUF_SIZE: usize = 128;

    let key = [0xab;32];
    let mut magma = MagmaMode::new(key, CipherMode::CFB);

    let txt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.\n";

    // building data containing 5000x of txt
    let repeat_count = 5000;
    let mut source = Vec::<u8>::with_capacity(txt.len() * repeat_count);
    (0..repeat_count).for_each(|_|source.extend_from_slice(txt));

    println!("Source len:{}", source.len());

    let mut encrypted = Vec::<u8>::with_capacity(source.len());
    let source_chunks = source.chunks(BUF_SIZE);
    for chunk in source_chunks {
        let mut ciphertext = magma.encrypt(&chunk);
        encrypted.append(&mut ciphertext);
    }
    println!("Encrypted len:{}", encrypted.len());

    let mut decrypted = Vec::<u8>::with_capacity(encrypted.len());
    let encrypted_chunks = encrypted.chunks(BUF_SIZE);
    for chunk in encrypted_chunks {
        let mut plaintext = magma.decrypt(&chunk);
        decrypted.append(&mut plaintext);
    }
    println!("Decrypted len:{}", encrypted.len());

    if magma.get_mode().has_padding() {
        // remove padding bytes
        decrypted.truncate(source.len());
    }
    println!("Decrypted final len:{}", encrypted.len());

    assert_eq!(decrypted, source);
    println!("Completed.");
}
