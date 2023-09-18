# Symmetric Key Block Cipher "Magma" in Rust

[![crates.io](https://img.shields.io/crates/v/cipher_magma)](https://crates.io/crates/cipher_magma)
[![docs](https://img.shields.io/docsrs/cipher_magma)](https://docs.rs/cipher_magma)
[![build & test](https://github.com/sheroz/magma/actions/workflows/ci.yml/badge.svg)](https://github.com/sheroz/magma/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/github/license/sheroz/cipher_magma)](https://github.com/sheroz/magma/tree/main/cipher_magma/LICENSE.txt)

The brief description: [https://sheroz.com/pages/blog/rust-cipher-magma-28147-89.html](https://sheroz.com/pages/blog/rust-cipher-magma-28147-89.html)

## Supported Cipher Modes

- **ECB** - Electronic Codebook Mode
- **CTR** - Counter Encryption Mode
- **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html)
- **OFB** - Output Feedback Mode
- **CBC** - Cipher Block Chaining Mode
- **CFB** - Cipher Feedback Mode
- **MAC** - Message Authentication Code Generation Mode

## Implemented and tested according to specifications

- [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015: Block Cipher "Magma"
- [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89
- Block Cipher Modes:
  - [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)
  - [CTR-ACPKM, Р 1323565.1.017—2018](https://standartgost.ru/g/%D0%A0_1323565.1.017-2018)

Tests are implemented using: [crypto_vectors](https://crates.io/crates/crypto_vectors)

## Tested on platforms

1. Linux Ubuntu 22.04 LTS / Intel® Core™ i7
2. MacOS Ventura 13.4 / Apple Macbook Pro M1

## Usage

Please look at [magma_samples](https://github.com/sheroz/magma/tree/main/magma_samples/src)

### Samples

- Block encryption [encrypt_block.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/encrypt_block.rs)
- Text encryption [encrypt_text.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/encrypt_text.rs)
- Message Authentication Code (MAC) [calculate_mac.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/calculate_mac.rs)
- Buffer encryption [encrypt_buffer.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/encrypt_buffer.rs)
- Buffer encryption by parallel processing [encrypt_buffer_parallel.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/encrypt_buffer_parallel.rs)
  - On a MacBook M1 Pro with 8+2 cores, the encryption speed increased ~ 8.3 times
  - On an i7-3770 with 4 cores, running Linux, the encryption speed increased ~ 4.5 times
- File encryption [encrypt_file.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/encrypt_file.rs)
- Bitmap file encryption [encrypt_bmp.rs](https://github.com/sheroz/magma/blob/main/magma_samples/src/encrypt_bmp.rs)

## Bitmap file encryption results

### The original bitmap image: Ferris the crab

[![Ferris the crab, the original image](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/ferris.bmp)](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/ferris.bmp)

---

### Encrypted bitmap in Electronic Codebook (ECB) Mode

[![Ferris the crab, encrypted in ECB Mode](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_ecb.ferris.bmp)](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_ecb.ferris.bmp)

Please note that ECB has weaknesses. It does not hide data patterns well and leaks information about the plaintext. ECB mode [is not recommended](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB-weakness) for use in cryptographic protocols.

---

### Encrypted bitmap in Counter Encryption (CTR) Mode

[![Ferris the crab, encrypted in CTR Mode](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_ctr.ferris.bmp)](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_ctr.ferris.bmp)

---

### Encrypted bitmap in Output Feedback (OFB) Mode

[![Ferris the crab, encrypted in OFB Mode](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_ofb.ferris.bmp)](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_ofb.ferris.bmp)

---

### Encrypted bitmap in Cipher Block Chaining (CBC) Mode

[![Ferris the crab, encrypted in CBC Mode](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_cbc.ferris.bmp)](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_cbc.ferris.bmp)

---

### Encrypted bitmap in Cipher Feedback (CFB) Mode

[![Ferris the crab, encrypted in CFB Mode](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_cfb.ferris.bmp)](https://raw.githubusercontent.com/sheroz/magma/main/magma_samples/tests/out/encrypted_cfb.ferris.bmp)
