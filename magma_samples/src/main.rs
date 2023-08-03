fn main() {
    println!("\n***\n\nSample of block encryption\n");
    sample_encrypt_block();

    println!("\n***\n\nSample of text encryption\n");
    sample_encrypt_text();

    println!("\n***\n\nSample of Message Authentication Code (MAC) calculation\n");
    sample_calculate_mac();

    println!("\n***\n\nSample of Message Authentication Code (MAC) calculation in data chunks\n");
    sample_calculate_mac_data_chunks();
}

/// Sample of block encryption
fn sample_encrypt_block() {
    use cipher_magma::Magma;

    let mut magma = Magma::new();

    let cipher_key: [u32; 8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
        0xfcfdfeff,
    ];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    magma.set_key_u32(&cipher_key);

    let source = 0xfedcba9876543210_u64;
    println!("Source block:\n{:x}\n", source);

    let encrypted = magma.encrypt(source);
    println!("Encrypted ciphertext:\n{:x}\n", encrypted);

    let decrypted = magma.decrypt(encrypted);
    println!("Decrypted block:\n{:x}", decrypted);

    assert_eq!(decrypted, source);
}

/// Sample of text encryption
fn sample_encrypt_text() {
    use cipher_magma::{CipherMode, CipherOperation, Magma};

    let cipher_mode = CipherMode::CFB;

    let cipher_key = [0xab;32];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    let source_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.";

    println!("Source text:\n{}\n", source_text);

    let source_bytes = source_text.as_bytes();

    let mut magma = Magma::with_key_u8(&cipher_key);

    let encrypted = magma.cipher(source_bytes, &CipherOperation::Encrypt, &cipher_mode);
    println!("Encrypted ciphertext:\n{:02x?}\n", encrypted);

    let mut decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &cipher_mode);

    if cipher_mode.has_padding() {
        // remove padding bytes
        decrypted.truncate(source_bytes.len());
    }

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);

    assert_eq!(decrypted_text, source_text);
}

/// Sample of large data encryption in chunks
fn sample_encrypt_large_buffer() {
    use cipher_magma::{CipherMode, CipherOperation, Magma};

    let cipher_mode = CipherMode::CFB;

    let cipher_key = [0xab;32];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    let source_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.";

    println!("Source text:\n{}\n", source_text);

    let source_bytes = source_text.as_bytes();

    let mut magma = Magma::with_key_u8(&cipher_key);

    let encrypted = magma.cipher(source_bytes, &CipherOperation::Encrypt, &cipher_mode);
    println!("Encrypted ciphertext:\n{:02x?}\n", encrypted);

    let mut decrypted = magma.cipher(&encrypted, &CipherOperation::Decrypt, &cipher_mode);

    if cipher_mode.has_padding() {
        // remove padding bytes
        decrypted.truncate(source_bytes.len());
    }

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);

    assert_eq!(decrypted_text, source_text);
}

/// Sample of Message Authentication Code (MAC) calculation
fn sample_calculate_mac() {
    use cipher_magma::{mac, Magma};

    let cipher_key: [u32; 8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
        0xfcfdfeff,
    ];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    let message = [
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d,
        0x20, 0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5,
        0x7e, 0x41,
    ];
    println!("Message:\n{:02x?}\n", message);

    let mut magma = Magma::with_key_u32(&cipher_key);
    let mac = mac::calculate(&mut magma, &message);
    println!("Calculated MAC:\n{:x}\n", mac);
    assert_eq!(mac, 0x154e7210);
}

/// Sample of Message Authentication Code (MAC)
/// Updating context with data chunks and finalizing result
fn sample_calculate_mac_data_chunks() {
    use cipher_magma::{mac, Magma};

    let cipher_key: [u8; 32] = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
        0xfe, 0xff,
    ];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    let mut magma = Magma::with_key_u8(&cipher_key);

    let message = [
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59, 0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d,
        0x20, 0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c, 0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5,
        0x7e, 0x41,
    ];
    println!("Message:\n{:02x?}\n", message);

    // update the context
    for chunk in message.chunks(8) {
        mac::update(&mut magma, &chunk);
    }

    // finalize and get result
    let mac = mac::finalize(&mut magma);
    println!("Calculated MAC:\n{:x}\n", mac);

    assert_eq!(mac, 0x154e7210);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_test() {
        main();
    }

    #[test]
    fn sample_encrypt_block_test() {
        sample_encrypt_block();
    }

    #[test]
    fn sample_encrypt_text_test() {
        sample_encrypt_text();
    }

    #[test]
    fn sample_calculate_mac_test() {
        sample_calculate_mac();
    }

    #[test]
    fn sample_calculate_mac_update_test() {
        sample_calculate_mac_data_chunks();
    }
}
