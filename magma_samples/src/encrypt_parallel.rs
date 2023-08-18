/// Sample of buffer encryption in chunks by parallel processing
pub fn encrypt_buffer_parallel() {
    use cipher_magma::{CipherMode, MagmaStream};

    const CHUNK_SIZE: usize = 4096;

    let key = [0xab; 32];
    let mut magma = MagmaStream::new(key, CipherMode::CTR);

    let txt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.\n";

    // build the source buffer containing 50000x of txt ~ 16 MB
    let repeat_count = 50000;
    let mut source = Vec::<u8>::with_capacity(txt.len() * repeat_count);
    (0..repeat_count).for_each(|_| source.extend_from_slice(txt));
    println!("Source len:{}", source.len());

    let chunks = source.chunks(CHUNK_SIZE);
    println!("Chunk size:{}", CHUNK_SIZE);
    println!("Chunks count:{}", chunks.clone().count());

    println!("Encrypting...");
    let mut encrypted = Vec::<u8>::with_capacity(source.len());
    for chunk in chunks {
        let mut ciphertext = magma.encrypt(chunk);
        encrypted.append(&mut ciphertext);
    }
    println!("Encrypted len:{}", encrypted.len());

    println!("Decrypting...");
    let mut decrypted = Vec::<u8>::with_capacity(encrypted.len());
    let encrypted_chunks = encrypted.chunks(CHUNK_SIZE);
    for chunk in encrypted_chunks {
        let mut plaintext = magma.decrypt(&chunk);
        decrypted.append(&mut plaintext);
    }
    println!("Decrypted len:{}", encrypted.len());

    // remove padding bytes
    if magma.get_mode().has_padding() {
        decrypted.truncate(source.len());
    }
    println!("Decrypted final len:{}", encrypted.len());

    assert_eq!(decrypted, source);

    println!("Completed.");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_buffer_parallel_test() {
        encrypt_buffer_parallel();
    }
}
