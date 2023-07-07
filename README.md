# Block Cipher "Magma" (GOST R 34.12-2015, former GOST 28147-89)

## Implemented and tested according to specifications

1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015
2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89

## Tested on platforms

1. Linux Ubuntu 22.04 LTS / Intel® Core™ i7
2. MacOS Ventura 13.4 / Apple Macbook Pro M1

## Sample usage

### Please look at [src/bin/sample.rs](src/bin/sample.rs)

#### Block encryption sample

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

#### Text encryption sample

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
    let mut magma = Magma::new_with_key(&cipher_key);
    let encrypted = magma.encrypt_buffer(source_bytes, CipherMode::ECB);
    println!("Encrypted ciphertext:\n{:x?}\n", encrypted);

    let mut decrypted = magma.decrypt_buffer(&encrypted, CipherMode::ECB);

    // remove padding bytes
    decrypted.truncate(source_bytes.len());

    let decrypted_text = String::from_utf8(decrypted).unwrap();
    println!("Decrypted text:\n{}\n", decrypted_text);

Output:

    Source text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.

    Encrypted ciphertext:
    [c7, 28, af, af, 1f, 85, e0, 72, de, ca, 29, a4, b0, 1f, 13, 19, df, 5b, 38, 65, 95, b1, 31, b3, 29, 68, c7, 4d, 18, 72, 4a, 21, 1d, 66, 93, c, a7, 3, a2, b1, 19, 33, fd, ec, 19, cd, ae, 19, 61, 13, 54, c4, 41, 5, c1, d9, 13, e, d4, 7f, 23, 5c, 9d, 80, f8, d5, 67, a4, b3, cf, ef, 50, ba, 3f, 12, 96, 1a, a, f9, 55, 25, e6, da, 33, 1a, 4e, e0, f1, 5f, be, d2, a7, a7, f, ff, 4d, b5, 87, f3, e6, a8, a, 1c, 4c, ce, f0, 10, e2, c3, b2, 3c, b2, 38, de, 2b, a, ae, d0, e4, 83, b0, a6, 34, d5, 89, 8a, ca, f2, d6, 11, 73, f5, e8, a6, c5, 91, e, 76, 2d, 62, 87, 6c, 7b, 68, 2a, 70, d4, b8, d0, ef, 91, 6e, 7f, 6d, 38, f, 5b, 10, db, b2, 34, c4, 39, 2d, 74, 9e, 1, ea, 36, 18, 54, 8a, dd, 27, bd, e6, f6, 6c, e5, 8d, 7a, 3b, cb, e, cf, 70, 2c, 8f, c0, 4e, b1, b1, 68, 8, 45, c4, 1e, a9, 70, 67, 25, 39, 62, 49, b4, 63, 57, a9, d7, 5a, 94, 38, 42, c1, e1, b8, 2b, 1e, 49, 9e, 44, 83, 6, 35, 2b, a7, ab, da, b1, b4, 7, 3, 2b, 8e, 2f, bd, 5a, b2, ca, 65, 6b, 4a, 3, 51, be, b9, 18, a8, 67, 8e, 4f, a1, 4f, 2b, cd, 6d, 87, a5, 3d, 8b, 15, b2, 46, 84, eb, 2, 4b, 7d, bd, 99, c3, d0, 7e, 4, a6, 7f, 6e, 9d, 93, e0, 69, bd, d3, 67, cf, 97, 96, bb, 2f, 48, df, ad, 28, ec, 53, 8c, 38, 85, e7, b2, 9e, de, ff, b0, 55, d0, ab, 9a, 91, 47, d4, dd, 30, 61, 42, c1, c3, 7a, 89, a3, b2, 2d, 73, c2, 98, b3, 19, 6e, ee, c4, c1, 9b, 3e, 7e, d5, 55]

    Decrypted text:
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. Quisque iaculis est et est volutpat posuere.
