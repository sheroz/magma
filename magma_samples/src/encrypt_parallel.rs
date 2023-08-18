use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Sample of buffer encryption by parallel processing
pub fn encrypt_buffer_parallel() {
    use cipher_magma::{CipherMode, MagmaStream};
    use rayon::prelude::*;

    const CHUNK_SIZE: usize = 128;

    let key = [0xab; 32];
    let mut magma = MagmaStream::new(key, CipherMode::CTR);

    let txt = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.\n";

    // build the source buffer containing 50000x of txt ~ 16 MB
    let repeat_count = 1;
    let mut source = Vec::<u8>::with_capacity(txt.len() * repeat_count);
    (0..repeat_count).for_each(|_| source.extend_from_slice(txt));
    println!("Source len:{}", source.len());

    let chunks = source.chunks(CHUNK_SIZE);
    println!("Chunk size:{}", CHUNK_SIZE);
    println!("Chunks count:{}", chunks.clone().count());

    println!("Encrypting...");
    let mut encrypted = Vec::<u8>::with_capacity(source.len());

    let mutex = Arc::new(Mutex::new(HashMap::<usize, Vec<u8>>::new()));
    source
        .par_chunks(CHUNK_SIZE)
        .enumerate()
        .for_each(|(index, chunk)| {
            let mut counter = (index * CHUNK_SIZE) as u64;
            if counter > 0 {
                counter -= 1;
            }

            let (ciphertext, _) = cipher_magma::ctr::cipher_ctr_core(&magma, chunk, counter);
            mutex.lock().unwrap().insert(index, ciphertext);
        });

    // merge encrypted chunks
    let mut map = mutex.lock().unwrap();
    let mut map_keys = map.keys().map(|v| *v).collect::<Vec<_>>();
    map_keys.sort();
    map_keys
        .iter()
        .for_each(|index| encrypted.append(map.get_mut(index).unwrap()));

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
