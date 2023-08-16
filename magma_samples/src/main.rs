mod encrypt_block;
mod encrypt_text;
mod encrypt_large_buffer;
mod encrypt_file;
mod calculate_mac;

use encrypt_block::*;
use encrypt_text::*;
use encrypt_large_buffer::*;
use calculate_mac::*;
use encrypt_file::*;

fn main() {
    println!("\n***\n\nBlock encryption\n");
    encrypt_block();

    println!("\n***\n\nText encryption\n");
    encrypt_text();

    println!("\n***\n\nEncrypting of large buffer in chunks\n");
    encrypt_buffer();

    println!("\n***\n\nMessage Authentication Code (MAC) calculation\n");
    calculate_mac();

    println!("\n***\n\nMessage Authentication Code (MAC) calculation in data chunks\n");
    calculate_mac_data_chunks();

    println!("\n***\n\nFile encryption\n");
    encrypt_file();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_test() {
        main();
    }

    #[test]
    fn encrypt_block_test() {
        encrypt_block();
    }

    #[test]
    fn encrypt_text_test() {
        encrypt_text();
    }
 
    #[test]
    fn encrypt_large_buffer_test() {
        encrypt_buffer();
    }

    #[test]
    fn calculate_mac_test() {
        calculate_mac();
    }

    #[test]
    fn calculate_mac_update_test() {
        calculate_mac_data_chunks();
    }
}
