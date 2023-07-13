use cipher_magma::{Magma, CipherMode};

fn main() {
    sample_encrypt_block();
    sample_encrypt_text_ecb(); 
    sample_generate_mac();
}

/// Block encryption sample
fn sample_encrypt_block() {
    let mut magma = Magma::new();

    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    magma.set_key(&cipher_key);

    let source = 0xfedcba9876543210_u64;
    println!("Source block: {:x}", source);

    let encrypted = magma.encrypt(source);
    println!("Encrypted ciphertext: {:x}", encrypted);

    let decrypted = magma.decrypt(encrypted);
    println!("Decrypted block: {:x}", decrypted);
}

/// Buffer encryption sample in ECB mode
fn sample_encrypt_text_ecb() {
    let source_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.";

    println!("Source text:\n{}\n", source_text);

    let source_bytes = source_text.as_bytes();

    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    let mut magma = Magma::with_key(&cipher_key);
    let encrypted = magma.encrypt_buffer(source_bytes, CipherMode::ECB);
    println!("Encrypted ciphertext:\n{:x?}\n", encrypted);

    let mut decrypted = magma.decrypt_buffer(&encrypted, CipherMode::ECB);

    // remove padding bytes
    decrypted.truncate(source_bytes.len());

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);
}

/// MAC generation sample
fn sample_generate_mac() {
    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    let source_buffer = [
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
        0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
        0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
        0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
    ];
    println!("Source buffer:\n{:x?}\n", source_buffer);

    let mut magma = Magma::with_key(&cipher_key);
    let mac = magma.generate_mac(&source_buffer);
    println!("Generated MAC:\n{:x}\n", mac);
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
    fn sample_encrypt_text_ecb_test() {
        sample_encrypt_text_ecb();
    }

    #[test]
    fn sample_generate_mac_test() {
        sample_generate_mac();
    }
}