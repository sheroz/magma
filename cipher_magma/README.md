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

Please look at [magma_samples](https://github.com/sheroz/magma/tree/main/magma_samples/src/samples)

### Block encryption sample: [encrypt_block.rs](https://github.com/sheroz/magma/tree/main/magma_samples/src/samples/encrypt_block.rs)

```rust
use cipher_magma::Magma;

let key: [u32; 8] = [
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb,
    0xfcfdfeff,
];
println!("Key:\n{:x?}\n", key);
let magma = Magma::with_key(key);

let source = 0xfedcba9876543210_u64;
println!("Source:\n{:x}\n", source);

let encrypted = magma.encrypt(source);
println!("Encrypted:\n{:x}\n", encrypted);

let decrypted = magma.decrypt(encrypted);
println!("Decrypted:\n{:x}", decrypted);

assert_eq!(decrypted, source);
```

### Text encryption sample: [encrypt_text.rs](https://github.com/sheroz/magma/tree/main/magma_samples/src/samples/encrypt_text.rs)

```rust
use cipher_magma::{CipherMode, MagmaStream};

let key = [0xab; 32];
println!("Key:\n{:x?}\n", key);
let mut magma = MagmaStream::new(key, CipherMode::CFB);

let source = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
    Aenean ac sem leo. Morbi pretium neque eget felis finibus convallis. \
    Praesent tristique rutrum odio at rhoncus. Duis non ligula ut diam tristique commodo. \
    Phasellus vel ex nec leo pretium efficitur. Aliquam malesuada vestibulum magna. \
    Quisque iaculis est et est volutpat posuere.";

println!("Source:\n{}\n", String::from_utf8(source.to_vec()).unwrap());

let encrypted = magma.encrypt(source);
println!("Encrypted:\n{:02x?}\n", encrypted);

let mut decrypted = magma.decrypt(&encrypted);

if magma.get_mode().has_padding() {
    // remove padding bytes
    decrypted.truncate(source.len());
}

assert_eq!(decrypted, source);
println!("Decrypted:\n{}\n", String::from_utf8(decrypted).unwrap());
```

### Message Authentication Code (MAC) sample: [calculate_mac.rs](https://github.com/sheroz/magma/tree/main/magma_samples/src/samples/calculate_mac.rs)

```rust
use cipher_magma::{mac, CipherMode, MagmaStream};

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

// update the context
for chunk in message.chunks(8) {
    mac::update(&mut magma, &chunk);
}

// finalize and get result
let mac = mac::finalize(&mut magma);
println!("Calculated MAC:\n{:x}\n", mac);

assert_eq!(mac, 0x154e7210);
```

### File encryption sample: [encrypt_file.rs](https://github.com/sheroz/magma/tree/main/magma_samples/src/samples/encrypt_file.rs)

```rust
use cipher_magma::{CipherMode, MagmaStream};
use std::env;
use std::fs::File;
use std::io::{Read, Seek, Write};

let key = [0xab; 32];
let mut magma = MagmaStream::new(key, CipherMode::CBC);

// opening source file
let source_filename = "README.md";
println!("Opening source file: {}", source_filename);

let mut source_file = File::open(source_filename).expect("Could not open file.");
let source_len = source_file.metadata().unwrap().len();

let temp_dir = env::temp_dir();

// creating file for encrypted data
let encrypted_filename = format!("{}.encrypted", source_filename);
let encrypted_filepath = temp_dir.join(encrypted_filename);
println!("Creating encrypted file: {:?}", encrypted_filepath);

let mut encrypted_file = File::options()
    .write(true)
    .read(true)
    .create(true)
    .open(encrypted_filepath)
    .expect("Could not create encrypted file.");

println!("Encrypting ...");

// ensure buf size % 8 bytes
let mut buf = [0u8; 1024];

loop {
    let read_count = source_file
        .read(&mut buf)
        .expect("Could not read source file");

    if read_count == 0 {
        break;
    }

    let ciphertext = magma.encrypt(&buf[0..read_count]);

    encrypted_file
        .write_all(&ciphertext)
        .expect("Could not write into encrypted file");
}

encrypted_file
    .flush()
    .expect("Could not flush the encrypted file");

println!("Encryption completed.");

let decrypted_filename = format!("{}.decrypted", source_filename);
let decrypted_filepath = temp_dir.join(decrypted_filename);

println!("Creating file for decrypted data: {:?}", decrypted_filepath);

let mut decrypted_file =
    File::create(decrypted_filepath).expect("Could not create decrypted file.");

println!("Decrypting ...");

// rewind the file position to the begining
encrypted_file
    .rewind()
    .expect("Could not rewind encrypted file");

loop {
    let read_count = encrypted_file
        .read(&mut buf)
        .expect("Could not read encrypted file");

    if read_count == 0 {
        break;
    }

    let plaintext = magma.decrypt(&buf[0..read_count]);

    decrypted_file
        .write_all(&plaintext)
        .expect("Could not write into decrypted file");
}

decrypted_file
    .flush()
    .expect("Could not flush the decrypted file");

if magma.get_mode().has_padding() {
    // remove padding bytes
    decrypted_file
        .set_len(source_len)
        .expect("Could not remove padding bytes from decrypted file");
}

println!("Decryption completed.");
```
