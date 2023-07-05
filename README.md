# Implementation of crypto algorithms in Rust

## Symmetric Block Ciphers

### Block Cipher Magma (GOST R 34.12-2015, former GOST 28147-89)

Implemented and tested according:

1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) GOST R 34.12-2015
2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) GOST 28147-89

#### Sample block encryption

    let mut gost = magma::CryptoEngine::new();

    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    gost.set_key(&cipher_key);

    let source = 0xfedcba9876543210_u64;
    println!("Source: {:x}", source);

    let encrypted = gost.encrypt(source);
    println!("Encrypted ciphertext: {:x}", encrypted);

    let decrypted = gost.decrypt(encrypted);
    println!("Decrypted source: {:x}", decrypted);

Output:

    Source: fedcba9876543210
    Encrypted ciphertext: 4ee901e5c2d8ca3d
    Decrypted source: fedcba9876543210

#### Sample text encryption

    let source_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
    Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis.";

    println!("Source text:\n{}\n", source_text);

    let source_bytes = source_text.as_bytes();

    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    let mut gost = magma::CryptoEngine::new_with_key(&cipher_key);
    let encrypted = gost.encrypt_buf(source_bytes, magma::Mode::ECB);
    println!("Encrypted ciphertext:\n{:x?}\n", encrypted);

    let mut decrypted = gost.decrypt_buf(&encrypted, magma::Mode::ECB);

    // truncate padding bytes
    decrypted.truncate(source_bytes.len());

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);

Output:

    Source text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis.

    Encrypted ciphertext:
    [21, 8a, 31, bd, 27, b1, 4f, 61, 57, cd, 4e, bc, 38, ed, 4d, 48, 33, de, 19, 2f, 9d, 19, 1d, 40, 5a, be, 62, 34, 1b, cc, 5a, 2a, d6, 4b, 1c, 36, 9e, 56, 26, 29, a1, 50, 47, 67, df, e3, 8d, ae, 4f, 59, b2, eb, b2, 3f, 41, f9, 1b, 9a, d0, d5, 8b, 8, b0, 4c, 42, 8b, c2, 86, 72, f9, 6e, 3a, 54, 78, ff, 29, 19, 42, d3, d0, 8b, 4b, 9f, 66, cd, 14, ff, de, ec, ee, c2, a3, cd, 6d, 64, 4f, 3c, 5c, 41, f0, 87, f2, ee, 4c, f8, 18, d9, bc, 2c, bb, ab, 47, ce, 3, 1, 15, b5, 8d, 82, e9, f, 60, 10, 8, 4a, a6, b7, 9a]

    Decrypted text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis.

## Asymmetric Ciphers

WIP: RSA
