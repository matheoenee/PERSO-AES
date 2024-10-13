// This implementation is done by following this paper : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
use aes::aes::encryption::*; 
use aes::aes::decryption::*;

fn main() {
    println!("AES Encryption and Decryption Test Program");

    // Example AES-128 key and plaintext
    let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xcf, 0x09, 0x30, 0x86, 0x52, 0x14];
    let plaintext: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

    // Encrypt the plaintext
    let ciphertext = aes_encrypt(plaintext, &key);
    println!("Ciphertext: {:?}", ciphertext);

    // Decrypt the ciphertext back to the original plaintext
    let decrypted_plaintext = aes_decrypt(ciphertext, &key);
    println!("Decrypted Plaintext: {:?}", decrypted_plaintext);

    // Check if decryption matches the original plaintext
    if decrypted_plaintext == plaintext {
        println!("Decryption was successful, plaintext matches the original!");
    } else {
        println!("Decryption failed, plaintext does not match the original!");
    }
}
