use crate::aes::functions::*;

pub fn aes_encrypt(input: [u8; 16], key: &[u8]) -> [u8; 16] {
    let mut state = input;
    let nr = get_nr(key.len());
    let expanded_key = key_expansion(key, nr);

    // first round
    add_round_key(&mut state, &expanded_key[..16]);

    for round in 1..nr {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &expanded_key[round*16..(round+1)*16]);
    }

    // final round
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &expanded_key[nr*16..]);

    state
}

