# Implementation of crypto algorithms in Rust

## Symmetric Block Ciphers

### Block Cipher Magma (GOST R 34.12-2015, former GOST 28147-89)

Implemented and tested according:

1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) GOST R 34.12-2015
2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) GOST 28147-89

#### Sample usage

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

## Asymmetric Ciphers

WIP: RSA
