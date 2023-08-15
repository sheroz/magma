/// File encryption sample
pub fn sample_encrypt_file() {
    use cipher_magma::{CipherMode, MagmaStream};
    use std::io::{Read, Seek, Write};

    let key = [0xab; 32];
    let mut magma = MagmaStream::new(key, CipherMode::CBC);

    // opening file
    let source_filename = "README.md";
    println!("Opening source file: {}", source_filename);

    let mut source_file = std::fs::File::open(source_filename).expect("Could not open file.");
    let source_len = source_file.metadata().unwrap().len();

    let temp_dir = std::env::temp_dir();

    // creating file for encrypted data
    let encrypted_filename = format!("{}.encrypted", source_filename);
    let encrypted_filepath = temp_dir.join(encrypted_filename);
    println!("Creating encrypted file: {:?}", encrypted_filepath);

    let mut encrypted_file = std::fs::File::options()
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

    println!("Creating decrypted file: {:?}", decrypted_filepath);

    let mut decrypted_file =
        std::fs::File::create(decrypted_filepath).expect("Could not create decrypted file.");

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
}
