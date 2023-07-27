# Block Cipher "Magma" (GOST R 34.12-2015, former GOST 28147-89)

[![crates.io](https://img.shields.io/crates/v/cipher_magma)](https://crates.io/crates/cipher_magma)
[![docs](https://img.shields.io/docsrs/cipher_magma)](https://docs.rs/cipher_magma)
[![build & test](https://github.com/sheroz/magma/actions/workflows/ci.yml/badge.svg)](https://github.com/sheroz/magma/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/github/license/sheroz/cipher_magma)](https://github.com/sheroz/magma/tree/main/cipher_magma/LICENSE.txt)

## Supported Cipher Modes

* **ECB** - Electronic Codebook Mode
* **CTR** - Counter Encryption Mode
* **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html)
* **OFB** - Output Feedback Mode
* **CBC** - Cipher Block Chaining Mode
* **CFB** - Cipher Feedback Mode
* **MAC** - Message Authentication Code Generation Mode

## Implemented and tested according to specifications

* [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015: Block Cipher "Magma"
* [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89
* Block Cipher Modes:
  * [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
  * [CTR-ACPKM, Р 1323565.1.017—2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)

Tests are implemented using: [crypto_vectors](https://crates.io/crates/crypto_vectors)

## Tested on platforms

1. Linux Ubuntu 22.04 LTS / Intel® Core™ i7
2. MacOS Ventura 13.4 / Apple Macbook Pro M1

## Usage

Please look at [magma_samples](https://github.com/sheroz/magma/tree/main/magma_samples/src/main.rs)

### Sample of block encryption

    use cipher_magma::Magma;

    let mut magma = Magma::new();

    let cipher_key: [u32; 8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
        0xfcfdfeff,
    ];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    magma.set_key(&cipher_key);

    let source = 0xfedcba9876543210_u64;
    println!("Source block:\n{:x}\n", source);

    let encrypted = magma.encrypt(source);
    println!("Encrypted ciphertext:\n{:x}\n", encrypted);

    let decrypted = magma.decrypt(encrypted);
    println!("Decrypted block:\n{:x}", decrypted);

    assert_eq!(decrypted, source);

Output:

    Cipher key:
    [ffeeddcc, bbaa9988, 77665544, 33221100, f0f1f2f3, f4f5f6f7, f8f9fafb, fcfdfeff]

    Source block:
    fedcba9876543210

    Encrypted ciphertext:
    4ee901e5c2d8ca3d

    Decrypted block:
    fedcba9876543210

### Sample of text encryption

    use cipher_magma::{CipherMode, CipherOperation, Magma};

    let cipher_mode = CipherMode::CFB;

    let cipher_key: [u32; 8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
        0xfcfdfeff,
    ];
    println!("Cipher key:\n{:x?}\n", cipher_key);

    let source_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
        Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
        Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
        Quisque iaculis est et est volutpat posuere.";

    println!("Source text:\n{}\n", source_text);

    let source_bytes = source_text.as_bytes();

    let mut magma = Magma::with_key(&cipher_key);

    let initialization_vector = [0x1234567890abcdef_u64, 0x234567890abcdef1_u64];
    magma.set_iv(&initialization_vector);

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

Output:

    Cipher key:
    [ffeeddcc, bbaa9988, 77665544, 33221100, f0f1f2f3, f4f5f6f7, f8f9fafb, fcfdfeff]

    Source text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.

    Encrypted ciphertext:
    [05, 86, 62, ec, 37, a3, 5f, aa, a5, 67, ce, 68, 83, ed, f9, d3, de, 9a, bd, 97, b0, f7, 8b, af, b8, cd, 03, 7f, 4c, ed, 4b, fe, d5, c0, a9, 65, 55, de, ca, 6c, 1c, 28, 38, fb, a4, 93, d0, 24, 86, d0, 7f, dd, ea, d4, 36, 16, 3d, c0, 09, da, 65, 0a, ec, 02, 3c, 1b, 1b, c6, f8, dc, 5c, 93, 23, e5, 33, 8c, 5c, 1e, dd, 59, b0, 6e, 8c, 0c, 08, d2, a1, 38, f5, 7c, 93, ff, d8, c2, f8, 1d, 5d, 30, 69, 22, a2, 2c, 1d, 26, 36, e7, 1f, f4, 06, b5, 0b, ef, 18, 13, 69, b1, e2, 12, c0, 20, e1, d7, 45, 28, a6, 0c, 46, 67, 9f, 27, dd, 7c, bd, 3b, 19, 08, 16, 3c, 1a, 13, 11, f2, c0, 44, 66, 5d, a1, 24, c1, ca, f9, 0d, 70, 3e, ea, ac, 8f, a7, 65, e3, bb, 8d, 80, 2f, fd, fa, be, 36, 90, e2, 0c, b0, 5f, 74, 4b, 38, 7c, bb, 9c, 58, 6d, 15, fc, 80, 16, 4d, b5, 4a, 37, 32, 06, d6, a2, 6c, 44, 69, 64, 83, b8, 31, 31, 09, 16, 68, f3, 7a, f5, 97, 99, c9, 38, e6, 5d, f0, d7, 18, 91, e5, b1, 71, d4, 23, 68, 9e, 2d, d0, d7, f7, f0, 89, c7, dc, 87, 72, fd, e8, e0, 40, 0d, 1b, 68, 7b, 13, 00, 8a, 52, af, 25, f3, ce, e4, cc, e3, 75, 70, 9a, 67, 41, 83, 37, d9, 0a, 5e, cb, b9, a7, 4a, 03, 27, b6, 0a, 70, 91, 26, d7, 1c, 15, 98, 75, 49, 32, d7, 30, 1c, 8d, 6d, 95, a1, e8, b2, b1, 07, 3e, 76, f0, b3, c4, 45, 65, 7b, ee, c4, 7b, ed, a9, f7, af, 97, 5e, a9, 27, 0c, 4a, 51, ce, e8, b9, 1a, 8c, ce, 36, d2, e6, e7, 57, bc, cf, 5d, 68, 0f, cb, f3, 92, e5, 23, 7e]

    Decrypted text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.

### Sample of Message Authentication Code (MAC) calculation

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

    let mut magma = Magma::with_key(&cipher_key);
    let mac = mac::calculate(&mut magma, &message);
    println!("Calculated MAC:\n{:x}\n", mac);

Output:

    Cipher key:
    [ffeeddcc, bbaa9988, 77665544, 33221100, f0f1f2f3, f4f5f6f7, f8f9fafb, fcfdfeff]

    Message:
    [92, de, f0, 6b, 3c, 13, 0a, 59, db, 54, c7, 04, f8, 18, 9d, 20, 4a, 98, fb, 2e, 67, a8, 02, 4c, 89, 12, 40, 9b, 17, b5, 7e, 41]

    Calculated MAC:
    154e7210
