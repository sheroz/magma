use cipher_magma::{Magma, CipherOperation, CipherMode};

fn main() {
    println!("\n***\n\nSample of block encryption:");
    sample_encrypt_block();

    println!("\n***\n\nSample of text encryption in OFB mode:");
    sample_encrypt_text_ofb(); 

    println!("\n***\n\nSample of Message Authentication Code (MAC) generation:");
    sample_generate_mac();
}

/// Sample of block encryption 
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

/// Sample of text encryption sample in Output Feedback (OFB) mode
fn sample_encrypt_text_ofb() {
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
    
    let encrypted = magma.cipher(source_bytes, CipherOperation::Encrypt, CipherMode::OFB);
    println!("Encrypted ciphertext:\n{:x?}\n", encrypted);

    let decrypted = magma.cipher(&encrypted, CipherOperation::Decrypt, CipherMode::OFB);

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);
}

/// Message Authentication Code (MAC) sample
fn sample_generate_mac() {
    let security_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    println!("Security key:\n{:x?}\n", security_key);

    let message = [
        0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
        0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
        0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
        0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
    ];
    println!("Message:\n{:x?}\n", message);

    let mut magma = Magma::with_key(&security_key);
    let mac = magma.cipher_mac(&message);
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
        sample_encrypt_text_ofb();
    }

    #[test]
    fn sample_generate_mac_test() {
        sample_generate_mac();
    }
}