use crate::aes::functions::*;

pub fn aes_decrypt(input: [u8; 16], key: &[u8]) -> [u8; 16] {
    let mut state = input;
    let nr = get_nr(key.len());
    let expanded_key = key_expansion(key, nr);

    // first round
    add_round_key(&mut state, &expanded_key[nr*16..(nr+1)*16]);

    for round in (1..nr).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &expanded_key[16*round..16*(round+1)]);
        inv_mix_columns(&mut state);
    }

    // final round
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &expanded_key[..16]);

    state
}