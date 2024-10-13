// This implementation is done by following this paper : https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
use aes::aes::encryption::*; // Import the AES encryption function
use aes::aes::functions::*; // Import key expansion if needed

fn main() {
    println!("Welcome to AES Encryption programm!");

    let mut state = [0u8; 16];
    for i in 0u8..16{
        state[i as usize] = i;
    }
    println!("state : {:?}", state);

    mix_columns(&mut state);

    println!("state : {:?}", state);

    inv_mix_columns(&mut state);

    println!("state : {:?}", state);
}
