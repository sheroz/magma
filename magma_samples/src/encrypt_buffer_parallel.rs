/// Sample of buffer encryption by parallel processing of chunks
/// Results (MacBook Pro M1 2021):
/// 
/// ```text
/// Source len: 16850000
/// Encrypting by parallel processing...
/// Encryption, elapsed ticks: 19012211
/// Encrypted len: 16850000
/// Decrypting in single thread...
/// Decryption, elapsed ticks: 156965972
/// Parallel processing speedup: 8.256060907382103
/// Decrypted len: 16850000
/// Decrypted final len: 16850000
/// Completed.
/// ```
pub fn encrypt_buffer_parallel() {
    use cipher_magma::{CipherMode, MagmaStream};
    use rayon::prelude::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

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
    println!("Source len: {}", source.len());

    println!("Encrypting by parallel processing...");
    let mut encrypted = Vec::<u8>::with_capacity(source.len());
    let counter_alignment = if CHUNK_SIZE % 8 == 0 { 0 } else { 1 };
    let mutex = Arc::new(Mutex::new(HashMap::<usize, Vec<u8>>::new()));
    let encrypt_start = tick_counter::start();
    source
        .par_chunks(CHUNK_SIZE)
        .enumerate()
        .for_each(|(index, chunk)| {
            let counter = counter_alignment + (index * CHUNK_SIZE / 8) as u64;
            let (ciphertext, _counter) = cipher_magma::ctr::cipher_ctr_core(&magma, chunk, counter);
            mutex.lock().unwrap().insert(index, ciphertext);
        });

    // merge encrypted chunks
    let mut map = mutex.lock().unwrap();
    let mut map_keys = map.keys().map(|v| *v).collect::<Vec<_>>();
    map_keys.sort();
    map_keys
        .iter()
        .for_each(|index| encrypted.append(map.get_mut(index).unwrap()));

    let encrypt_ticks = tick_counter::stop() - encrypt_start;
    println!("Encryption, elapsed ticks: {}", encrypt_ticks);
    println!("Encrypted len: {}", encrypted.len());

    println!("Decrypting in single thread...");
    let mut decrypted = Vec::<u8>::with_capacity(encrypted.len());
    let encrypted_chunks = encrypted.chunks(CHUNK_SIZE);
    let decrypt_start = tick_counter::start();
    for chunk in encrypted_chunks {
        let mut plaintext = magma.decrypt(&chunk);
        decrypted.append(&mut plaintext);
    }
    let decrypt_ticks = tick_counter::stop() - decrypt_start;
    let speedup = (decrypt_ticks as f64) / (encrypt_ticks as f64);
    println!("Decryption, elapsed ticks: {}", decrypt_ticks);
    println!("Parallel processing speedup: {}", speedup);

    println!("Decrypted len: {}", encrypted.len());

    // remove padding bytes
    if magma.get_mode().has_padding() {
        decrypted.truncate(source.len());
    }
    println!("Decrypted final len: {}", encrypted.len());

    assert_eq!(decrypted, source);

    println!("Completed.");
}
