mod samples;
use samples::encrypt_block::*;
use samples::encrypt_text::*;
use samples::encrypt_large_buffer::*;
use samples::calculate_mac::*;
use samples::encrypt_file::*;

fn main() {
    println!("\n***\n\nBlock encryption\n");
    sample_encrypt_block();

    println!("\n***\n\nText encryption\n");
    sample_encrypt_text();

    println!("\n***\n\nEncrypting of large buffer in chunks\n");
    sample_encrypt_large_buffer();

    println!("\n***\n\nMessage Authentication Code (MAC) calculation\n");
    sample_calculate_mac();

    println!("\n***\n\nMessage Authentication Code (MAC) calculation in data chunks\n");
    sample_calculate_mac_data_chunks();

    println!("\n***\n\nFile encryption\n");
    sample_encrypt_file();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_test() {
        main();
    }

    #[test]
    fn sample_encrypt_block_test() {
        sample_encrypt_block();
    }

    #[test]
    fn sample_encrypt_text_test() {
        sample_encrypt_text();
    }

    #[test]
    fn sample_encrypt_large_buffer_test() {
        sample_encrypt_large_buffer();
    }

    #[test]
    fn sample_calculate_mac_test() {
        sample_calculate_mac();
    }

    #[test]
    fn sample_calculate_mac_update_test() {
        sample_calculate_mac_data_chunks();
    }
}
