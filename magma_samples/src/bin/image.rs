use cipher_magma::{CipherMode, MagmaStream};
use image;
use std::env;
use std::path::Path;

pub fn main() {
    let source = Path::new("sample.bmp");
    encrypt_bmp(source, CipherMode::ECB);
    encrypt_bmp(source, CipherMode::CBC);
    encrypt_bmp(source, CipherMode::OFB);
    encrypt_bmp(source, CipherMode::CTR);
    encrypt_bmp(source, CipherMode::CFB);
}

pub fn encrypt_bmp(source_filepath: &Path, cipher_mode: CipherMode) {
    let img = image::open(source_filepath).unwrap();

    let buf = img.as_bytes();
    println!("buffer len: {}", buf.len());
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

    let filename = source_filepath.file_name().unwrap().to_str().unwrap();
    let enc_filename = format!(
        "encrypted_{}.{}",
        format!("{:?}", magma.get_mode()).to_lowercase(),
        filename
    );
    let enc_filepath = env::temp_dir().join(enc_filename);

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

#[test]
fn main_test() {
    main();
}
