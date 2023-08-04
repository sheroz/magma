use std::io::Seek;

/// File encryption sample
pub fn sample_encrypt_file() {
    use std::io::{Read, Write};

    use cipher_magma::{CipherMode, CipherOperation, Magma};

    let cipher_mode = CipherMode::CBC;
    let key = [0xab; 32];
    let mut magma = Magma::with_key_u8(&key);

    // opening file
    let source_filename = "README.md";
    println!("Opening source file: {}", source_filename);
    let mut source_file = std::fs::File::open(source_filename).expect("Could not open file.");
    let source_len = source_file.metadata().unwrap().len();

    // creating file for encrypted data
    let encrypted_filename = format!("{}.encrypted", source_filename);
    println!("Creating encrypted file: {}", encrypted_filename);
    let mut encrypted_file = std::fs::File::options()
        .write(true)
        .read(true)
        .create(true)
        .open(encrypted_filename)
        .expect("Could not create encrypted file.");

    println!("Encrypting ...");
    let mut buf = [0u8; 1024];
    loop {
        let read_count = source_file
            .read(&mut buf)
            .expect("Could not read source file");
        if read_count == 0 {
            break;
        }

        let mut ciphertext =
            magma.cipher(&buf[0..read_count], &CipherOperation::Encrypt, &cipher_mode);

        if cipher_mode.has_padding() {
            // remove padding bytes
            ciphertext.truncate(read_count);
        }

        encrypted_file
            .write_all(&ciphertext)
            .expect("Could not write into encrypted file");
    }
    encrypted_file.flush().expect("Could not flush the encrypted file");

    println!("Encryption completed.");

    let decrypted_filename = format!("{}.decrypted", source_filename);
    println!("Creating decrypted file: {}", decrypted_filename);
    let mut decrypted_file =
        std::fs::File::create(decrypted_filename).expect("Could not create decrypted file.");

    println!("Decrypting ...");

    // rewind the file position to the begining
    encrypted_file.rewind().expect("Could not rewind encrypted file");

    loop {
        let read_count = encrypted_file
            .read(&mut buf)
            .expect("Could not read encrypted file");
        if read_count == 0 {
            break;
        }

        let mut plaintext =
            magma.cipher(&buf[0..read_count], &CipherOperation::Decrypt, &cipher_mode);

        if cipher_mode.has_padding() {
            // remove padding bytes
            plaintext.truncate(read_count);
        }

        decrypted_file
            .write_all(&plaintext)
            .expect("Could not write into decrypted file");
    }
    decrypted_file.flush().expect("Could not flush the decrypted file");

    if cipher_mode.has_padding() {
        // remove padding bytes
        decrypted_file
            .set_len(source_len)
            .expect("Could not remove padding bytes from decrypted file");
    }

    println!("Decryption completed.");
}
