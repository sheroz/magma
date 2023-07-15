# Block Cipher "Magma" (GOST R 34.12-2015, former GOST 28147-89)

![Crates.io](https://img.shields.io/crates/v/cipher_magma)
![docs.rs](https://img.shields.io/docsrs/cipher_magma)
![build & test](https://github.com/sheroz/cipher_magma/actions/workflows/ci.yml/badge.svg)
![GitHub](https://img.shields.io/github/license/sheroz/cipher_magma)

## Supported Cipher Modes

Supported Cipher Modes: **ECB**, **CTR**, **CTR-ACPKM**, **OFB**, **MAC**

## Implemented and tested according to specifications

1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015
2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89
3. Block Cipher Modes: [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)  

## Tested on platforms

1. Linux Ubuntu 22.04 LTS / Intel® Core™ i7
2. MacOS Ventura 13.4 / Apple Macbook Pro M1

## Usage

Please look at [src/bin/sample.rs](src/bin/sample.rs)

### Sample of block encryption

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

Output:

    Source block: fedcba9876543210
    Encrypted ciphertext: 4ee901e5c2d8ca3d
    Decrypted block: fedcba9876543210

### Sample of text encryption in Output Feedback (OFB) mode

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
    
    let encrypted = magma.cipher(source_bytes, CipherOperation::Encrypt, CipherMode::Ofb);
    println!("Encrypted ciphertext:\n{:x?}\n", encrypted);

    let mut decrypted = magma.cipher(&encrypted, CipherOperation::Decrypt, CipherMode::Ofb);

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);

Output:

    Source text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.

    Encrypted ciphertext:
    [5, 86, 62, ec, 37, a3, 5f, aa, a5, 67, ce, 68, 83, ed, f9, d3, 98, 40, b8, 25, 50, 86, 51, 5f, 24, 42, 83, 3, c9, 95, cb, 37, 5e, 68, 77, 3f, 77, 88, 19, 40, c2, 3, 37, b9, 52, 5c, ce, d0, b5, 8, 58, 4a, 98, 22, e7, bd, 29, 66, 14, 70, ac, b2, 68, 2c, 6, b9, 5d, 1f, 92, f2, 64, 1c, 4b, 91, f0, a, 26, a8, e2, 8a, b7, d0, 47, fe, 46, b6, c8, 99, 93, b4, 51, 9e, d7, a2, 58, 7b, 51, b3, d5, 57, a6, 9c, 9b, ef, 24, 6d, a9, 55, 4e, f4, cc, e1, 6d, 84, dc, 2, 22, d2, b7, d6, bd, 61, 16, 32, 9e, 10, 43, 58, 81, 17, 8d, ec, 7d, fe, ed, ef, 66, 83, 7a, ad, 8c, d3, 99, 24, a7, 80, 2c, 94, 1f, 6c, 36, de, 3d, b2, 9, 77, 89, a3, c0, eb, 9c, bb, 27, 42, 47, 80, 78, a4, 10, fa, fe, da, 2, 3b, e0, c8, a5, e7, ed, e0, 25, 65, f2, 72, 72, 61, dc, a5, 7d, 7a, b1, 11, f0, 80, 50, 13, d6, fc, d9, 3d, 94, d7, 10, a5, d4, 44, 11, 10, d1, 19, f4, 43, aa, 24, 89, d2, e8, 50, 3f, 74, 88, 50, 51, 9b, bb, 2c, d3, 92, 3f, b5, 2a, eb, b9, 7b, 86, fa, 5f, f2, 76, 16, 99, 7, 44, 78, a9, ea, ec, c0, 34, 8b, cf, 48, 4c, ac, ff, 6b, b0, 2, 14, ce, 91, ff, 4b, 7c, d8, f7, ab, f4, ed, 53, b9, 76, 90, bd, 34, 67, 84, 44, ec, 2b, fe, 7b, db, 7a, 76, 9a, e7, 6, bf, 7f, 4, 99, 5e, 28, 44, 3f, 7, e4, e6, f1, ce, 40, f5, 9e, 8e, d5, 9, 47, 40, 82, d2, 5f, 3a, 47, 86, 2d, 53, 14, d6, 6a, 40, b7, b8, 57, ab, dc, a, d1, 95, b5, b9, 1c, 48, a0, 9d, 85]

    Decrypted text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.

### Sample of Message Authentication Code (MAC) generation

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

Output:

    Security key:
    [ffeeddcc, bbaa9988, 77665544, 33221100, f0f1f2f3, f4f5f6f7, f8f9fafb, fcfdfeff]

    Message:
    [92, de, f0, 6b, 3c, 13, a, 59, db, 54, c7, 4, f8, 18, 9d, 20, 4a, 98, fb, 2e, 67, a8, 2, 4c, 89, 12, 40, 9b, 17, b5, 7e, 41]

    Generated MAC:
    154e7210
