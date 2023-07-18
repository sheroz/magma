# Block Cipher "Magma" (GOST R 34.12-2015, former GOST 28147-89)

[![crates.io](https://img.shields.io/crates/v/cipher_magma)](https://crates.io/crates/cipher_magma)
[![docs](https://img.shields.io/docsrs/cipher_magma)](https://docs.rs/cipher_magma)
[![build & test](https://github.com/sheroz/cipher_magma/actions/workflows/ci.yml/badge.svg)](https://github.com/sheroz/cipher_magma/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/github/license/sheroz/cipher_magma)](https://github.com/sheroz/cipher_magma/blob/main/LICENSE.txt)

## Supported Cipher Modes

* **ECB** - Electronic Codebook Mode
* **CTR** - Counter Encryption Mode
* **CTR-ACPKM** - Counter Encryption Mode as per [RFC8645](https://www.rfc-editor.org/rfc/rfc8645.html)
* **OFB** - Output Feedback Mode
* **CBC** - Cipher Block Chaining Mode
* **CFB** - Cipher Feedback Mode
* **MAC** - Message Authentication Code Generation Mode

## Implemented and tested according to specifications

1. [RFC 8891](https://datatracker.ietf.org/doc/html/rfc8891.html) a.k.a GOST R 34.12-2015
2. [RFC 5830](https://datatracker.ietf.org/doc/html/rfc5830) a.k.a GOST 28147-89
3. Block Cipher Modes: [GOST R 34.13-2015](https://www.tc26.ru/standard/gost/GOST_R_3413-2015.pdf)  

## Tested on platforms

1. Linux Ubuntu 22.04 LTS / Intel® Core™ i7
2. MacOS Ventura 13.4 / Apple Macbook Pro M1

## Usage

Please look at [cipher_magma/samples](../cipher_magma/samples)
