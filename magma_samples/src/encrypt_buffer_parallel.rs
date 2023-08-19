/// Sample of buffer encryption by parallel processing in chunks
///
/// Results #1
/// MacBook Pro M1 2021
/// MacOS Ventura 13.4, Darwin Kernel Version 22.5.0
/// TLDR: parallel processing is ~8.3 times faster
///
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
///
/// ---
///
/// Results #2
/// Intel(R) Core(TM) i7-3770 CPU @ 3.40GHz
/// Linux 6.2.0-26-generic #26~22.04.1-Ubuntu x86_64
/// TLDR: parallel processing is ~ 4.5 times faster
///
/// Source len: 16850000
/// Encrypting by parallel processing...
/// Encryption, elapsed ticks: 8276437589
/// Encrypted len: 16850000
/// Decrypting in single thread...
/// Decryption, elapsed ticks: 37064304591
/// Parallel processing speedup: 4.478292042008655
/// Decrypted len: 16850000
/// Decrypted final len: 16850000
/// Completed.
/// 
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
    let mutex = Arc::new(Mutex::new(HashMap::<usize, Vec<u8>>::new()));
    let counter_size = CHUNK_SIZE / 8 + if CHUNK_SIZE % 8 == 0 { 0 } else { 1 };
    let encrypt_start = tick_counter::start();
    source
        .par_chunks(CHUNK_SIZE)
        .enumerate()
        .for_each(|(index, chunk)| {
            let counter = index * counter_size;
            let (ciphertext, _) = cipher_magma::ctr::cipher_ctr_core(&magma, chunk, counter as u64);
            mutex.lock().unwrap().insert(index, ciphertext);
        });

    // merging encrypted chunks
    let mut map = mutex.lock().unwrap();
    (0..map.len()).for_each(|index| encrypted.append(map.get_mut(&index).unwrap()));

    let encrypt_elapsed_ticks = tick_counter::stop() - encrypt_start;
    println!("Encryption, elapsed ticks: {}", encrypt_elapsed_ticks);

    println!("Encrypted len: {}", encrypted.len());

    println!("Decrypting in single thread...");
    let mut decrypted = Vec::<u8>::with_capacity(encrypted.len());
    let encrypted_chunks = encrypted.chunks(CHUNK_SIZE);

    let decrypt_start = tick_counter::start();
    for chunk in encrypted_chunks {
        // using the generic stream method to make sure of compatibility
        let mut plaintext = magma.decrypt(&chunk);
        decrypted.append(&mut plaintext);
    }

    let decrypt_elapsed_ticks = tick_counter::stop() - decrypt_start;
    let speedup = (decrypt_elapsed_ticks as f64) / (encrypt_elapsed_ticks as f64);
    println!("Decryption, elapsed ticks: {}", decrypt_elapsed_ticks);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_buffer_parallel_test() {
        encrypt_buffer_parallel();
    }
}
