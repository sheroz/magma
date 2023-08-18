mod calculate_mac;
mod encrypt_block;
mod encrypt_bmp;
mod encrypt_buffer;
mod encrypt_buffer_parallel;
mod encrypt_file;
mod encrypt_text;

fn main() {
    println!("\n***\n\nBlock encryption\n");
    encrypt_block::encrypt_block();

    println!("\n***\n\nText encryption\n");
    encrypt_text::encrypt_text();

    println!("\n***\n\nEncrypting buffer in chunks\n");
    encrypt_buffer::encrypt_buffer();

    println!("\n***\n\nEncrypting buffer by parallel processing of chunks\n");
    encrypt_buffer_parallel::encrypt_buffer_parallel();

    println!("\n***\n\nMessage Authentication Code (MAC) calculation\n");
    calculate_mac::calculate_mac();

    println!("\n***\n\nMessage Authentication Code (MAC) calculation in chunks\n");
    calculate_mac::calculate_mac_stream();

    println!("\n***\n\nFile encryption\n");
    encrypt_file::encrypt_file();

    println!("\n***\n\nBitmap image encryption\n");
    let bmp_filename = "ferris.bmp";
    encrypt_bmp::encrypt_bmp(bmp_filename, cipher_magma::CipherMode::ECB);
    encrypt_bmp::encrypt_bmp(bmp_filename, cipher_magma::CipherMode::CBC);
    encrypt_bmp::encrypt_bmp(bmp_filename, cipher_magma::CipherMode::OFB);
    encrypt_bmp::encrypt_bmp(bmp_filename, cipher_magma::CipherMode::CTR);
    encrypt_bmp::encrypt_bmp(bmp_filename, cipher_magma::CipherMode::CFB);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_test() {
        main();
    }
}
