# Implementation of Magma Symmetric Block Cipher (GOST R 34.12-2015, former GOST 28147-89) in Rust

## Implemented according

1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) GOST R 34.12-2015
2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) GOST 28147-89

## Tested on platforms

1. Linux Ubuntu 22.04 LTS / Intel® Core™ i7
2. MacOS Ventura 13.4 / Apple Macbook Pro M1

## Block encryption sample

    let mut gost = magma::CryptoEngine::new();

    let cipher_key: [u32;8] = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff
    ];
    gost.set_key(&cipher_key);

    let source = 0xfedcba9876543210_u64;
    println!("Source block: {:x}", source);

    let encrypted = gost.encrypt(source);
    println!("Encrypted ciphertext: {:x}", encrypted);

    let decrypted = gost.decrypt(encrypted);
    println!("Decrypted block: {:x}", decrypted);

Output:

    Source: fedcba9876543210
    Encrypted ciphertext: 4ee901e5c2d8ca3d
    Decrypted source: fedcba9876543210

## Text encryption sample

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
    let mut gost = magma::CryptoEngine::new_with_key(&cipher_key);
    let encrypted = gost.encrypt_buf(source_bytes, magma::Mode::ECB);
    println!("Encrypted ciphertext:\n{:x?}\n", encrypted);

    let mut decrypted = gost.decrypt_buf(&encrypted, magma::Mode::ECB);

    // remove padding bytes
    decrypted.truncate(source_bytes.len());

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);

Output:

    Source text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.

    Encrypted ciphertext:
    [21, 8a, 31, bd, 27, b1, 4f, 61, 57, cd, 4e, bc, 38, ed, 4d, 48, 33, de, 19, 2f, 9d, 19, 1d, 40, 5a, be, 62, 34, 1b, cc, 5a, 2a, d6, 4b, 1c, 36, 9e, 56, 26, 29, a1, 50, 47, 67, df, e3, 8d, ae, 4f, 59, b2, eb, b2, 3f, 41, f9, 1b, 9a, d0, d5, 8b, 8, b0, 4c, 42, 8b, c2, 86, 72, f9, 6e, 3a, 54, 78, ff, 29, 19, 42, d3, d0, 8b, 4b, 9f, 66, cd, 14, ff, de, ec, ee, c2, a3, cd, 6d, 64, 4f, 3c, 5c, 41, f0, 87, f2, ee, 4c, f8, 18, d9, bc, 2c, bb, ab, 47, ce, 3, 1, 15, b5, 8d, 82, e9, a7, ee, 9, 1a, aa, 34, 93, 5f, e8, 4f, be, 73, 15, 9b, 35, ff, b, b0, 74, 40, 61, cc, b, b7, d, dc, 35, 9c, a3, fb, d4, dc, 1a, c5, b6, f7, 2b, b4, 12, 39, 1e, 17, 25, 32, b4, 7e, 8d, 53, 26, e2, 38, b, 6c, 61, a6, 19, c9, a3, e2, 2c, 47, 8e, 65, cd, 1a, 37, 56, b1, 8c, ae, b1, d5, 21, b7, 0, e4, 5c, 1a, 28, 5b, 2b, 97, 22, ca, 88, 92, 12, 73, 63, e1, 4c, d2, fa, e8, ef, 8, 44, ac, 3c, 3e, ee, 99, 9f, 21, 1c, 27, d, a8, bc, dd, 20, c0, fd, 20, fc, 6f, f3, 4d, 4, bf, 76, 5b, 3f, f7, 1c, 5, 12, bc, 1c, 6, aa, 53, f6, 31, 39, 8b, 2b, c, 73, 30, af, 4d, 69, 44, e6, b1, b5, c7, 68, 38, fc, 8f, b5, 2f, f, 12, 1b, 5e, 64, 39, 51, 1d, 4, 41, 13, e0, 77, e4, 93, 90, 34, 51, de, 93, b4, 68, 75, 6a, 16, ed, df, 2d, 92, 99, 9f, 7a, fd, a5, 5a, b8, 1c, ee, fb, ba, 57, 70, d6, 9b, f5, 1f, e7, 66, 6a, 77, 7e, 81, a4, dc, 8b, 92, 1d, 54, c4, bd, 53, 4]

    Decrypted text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.
