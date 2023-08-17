use cipher_magma::{CipherMode, MagmaStream};
use image;
use std::env;
use std::path::PathBuf;

/// Bitmap image encryption sample
pub fn encrypt_bmp(filename: &str, cipher_mode: CipherMode) {
    
    // sample files are located in the /tests directory of the package root (magma_samples)
    let source_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");

    // let target_dir = env::temp_dir();
    // target directory is /tests/out of the package root (magma_samples)
    let target_dir = source_dir.join("out");

    let source_filepath = source_dir.join(filename);

    println!("Opening the image file: {:?} ...", source_filepath);
    let img = image::open(source_filepath).unwrap();

    let buf = img.as_bytes();
    assert!(buf.len() % 8 == 0);

    let key = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
        0xfe, 0xff,
    ];

    let mut magma = MagmaStream::new(key, cipher_mode);

    println!("Encrypting...");
    let enc_buf = magma.encrypt(&buf);
    assert_eq!(buf.len(), enc_buf.len());

    let enc_filename = format!(
        "encrypted_{}.{}",
        magma.get_mode().to_string().to_lowercase(),
        filename
    );
    let enc_filepath = target_dir.join(enc_filename);

    println!("Saving the encrypted image as: {:?}", enc_filepath);
    image::save_buffer(
        enc_filepath,
        &enc_buf,
        img.width(),
        img.height(),
        img.color(),
    )
    .unwrap();

    println!("Completed.");
}
