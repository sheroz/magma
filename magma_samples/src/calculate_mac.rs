/// Message Authentication Code (MAC) calculation
pub fn calculate_mac() {
    use cipher_magma::{mac, CipherMode, MagmaStream};

    let key: [u32; 8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
        0xfcfdfeff,
    ];
    println!("Key:\n{:x?}\n", key);

    let message = [
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d,
        0x20, 0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5,
        0x7e, 0x41,
    ];
    println!("Message:\n{:02x?}\n", message);

    let mut magma = MagmaStream::new(key, CipherMode::MAC);
    let mac = mac::calculate(&mut magma, &message);
    println!("Calculated MAC:{:x}", mac);
    assert_eq!(mac, 0x154e7210);

    println!("Completed.");
}

/// Message Authentication Code (MAC)
/// Updating context and finalizing result
pub fn calculate_mac_stream() {
    use cipher_magma::{mac, CipherMode, MagmaStream};

    const CHUNK_SIZE: usize = 16;

    let key: [u8; 32] = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
        0xfe, 0xff,
    ];
    println!("Key:\n{:x?}\n", key);

    let message = [
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d,
        0x20, 0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5,
        0x7e, 0x41,
    ];
    println!("Message:\n{:02x?}\n", message);

    let mut magma = MagmaStream::new(key, CipherMode::MAC);
    let chunks = message.chunks(16);
    println!("Chunk size:{}", CHUNK_SIZE);
    println!("Chunks count:{}", chunks.clone().count());

    // update the context in data chunks
    for chunk in chunks {
        mac::update(&mut magma, &chunk);
    }

    // finalize
    let mac = mac::finalize(&mut magma);
    println!("Calculated MAC:{:x}", mac);
    assert_eq!(mac, 0x154e7210);

    println!("Completed.");
}

#[cfg(test)] 
mod tests {
    use super::*;
    #[test]
    fn calculate_mac_test() {
        calculate_mac();
    }

    #[test]
    fn calculate_mac_stream_test() {
        calculate_mac_stream();
    }
}
