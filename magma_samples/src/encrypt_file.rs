/// File encryption sample
pub fn encrypt_file() {
    use cipher_magma::{CipherMode, MagmaStream};
    use std::fs::File;
    use std::io::{Read, Seek, Write};
    use std::path::PathBuf;

    let filename = "sample.md";

    // sample files are located in the /tests directory of the package root (magma_samples)
    let source_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

    // target directory is /tests/out of the package root (magma_samples)
    let target_dir = source_dir.join("out");

    let source_filepath = source_dir.join(filename);
    println!("Opening source file: {:?}", source_filepath);

    let mut source_file = File::open(&source_filepath).expect("Could not open the source file.");
    let source_len = source_file.metadata().unwrap().len();

    // creating file for encrypted data
    let encrypted_filepath = target_dir.join(format!("{}.encrypted", filename));
    println!("Creating encrypted file: {:?}", encrypted_filepath);

    let mut encrypted_file = File::options()
        .write(true)
        .read(true)
        .create(true)
        .open(encrypted_filepath)
        .expect("Could not create encrypted file.");

    // ensure buf size % 8 bytes
    let mut buf = [0u8; 1024];

    let key = [0xab; 32];
    let mut magma = MagmaStream::new(key, CipherMode::CBC);

    println!("Encrypting ...");
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

    let decrypted_filepath = target_dir.join(format!("decrypted.{}", filename));

    println!("Creating file for decrypted data: {:?}", decrypted_filepath);

    let mut decrypted_file =
        File::create(decrypted_filepath).expect("Could not create decrypted file.");

    // rewind the file position to the begining
    encrypted_file
        .rewind()
        .expect("Could not rewind encrypted file");

    println!("Decrypting ...");
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

    // remove padding bytes
    if magma.get_mode().has_padding() {
        decrypted_file
            .set_len(source_len)
            .expect("Could not remove padding bytes from decrypted file");
    }

    println!("Completed.");
}

#[cfg(test)] 
mod tests {
    use super::*;
    #[test]
    fn encrypt_file_test() {
        encrypt_file();
    }
}
