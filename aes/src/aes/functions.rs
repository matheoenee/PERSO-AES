use gf256::gf::gf256;
use crate::aes::utils::*;

fn get_nr(key_len: usize) -> usize {
    match key_len {
        16 => 10,
        24 => 12,
        32 => 14,
        _ => panic!("Invalid key length! Only 16, 24 or 32 bytes are supported."),
    }
}

pub fn key_expansion(key: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    let nr = get_nr(key_len);
    let mut expanded_key = vec![0u8; 4*(nr+1)*4];

    expanded_key[..key_len].copy_from_slice(&key);

    for i in (key_len..expanded_key.len()).step_by(4) {
        let mut temp = expanded_key[i-4..i].to_vec();
        if i % key_len == 0 {
            temp.rotate_left(1);
            for t in &mut temp {
                *t = S_BOX[*t as usize];
            }
            temp[0] ^= RCON[(i / key_len) - 1];
        }
        for j in 0..4 {
            expanded_key[i+j] = expanded_key[i+j - key_len] ^ temp[j];
        }
    }
    expanded_key
}

pub fn sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = S_BOX[state[i] as usize];
    }
}

pub fn inv_sub_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = INV_S_BOX[state[i] as usize];
    }
}

pub fn shift_rows(state: &mut [u8; 16]) {
    // second line
    state.swap(4, 7);
    state.swap(4, 6);
    state.swap(4, 5);
    // third line
    state.swap(8, 10);
    state.swap(9, 11);
    // fourth line
    state.swap(12, 13);
    state.swap(12, 14);
    state.swap(12, 15);
}

pub fn inv_shift_rows(state: &mut [u8; 16]) {
    // second line
    state.swap(4, 5);
    state.swap(4, 6);
    state.swap(4, 7);
    // third line
    state.swap(8, 10);
    state.swap(9, 11);
    // fourth line
    state.swap(12, 15);
    state.swap(12, 14);
    state.swap(12, 13);
}   

pub fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let a = [
            gf256::from(state[col]),
            gf256::from(state[col+4]),
            gf256::from(state[col+8]),
            gf256::from(state[col+12]),
        ];

        state[col] = ((a[0] * gf256::from(0x02)) + (a[1] * gf256::from(0x03)) + a[2] + a[3]).into();
        state[col + 4] = (a[0] + (a[1] * gf256::from(0x02)) + (a[2] * gf256::from(0x03)) + a[3]).into();
        state[col + 8] = (a[0] + a[1] + (a[2] * gf256::from(0x02)) + (a[3] * gf256::from(0x03))).into();
        state[col + 12] = ((a[0] * gf256::from(0x03)) + a[1] + a[2] + (a[3] * gf256::from(0x02))).into();
    }
}

pub fn inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let a = [
            gf256::from(state[col]),
            gf256::from(state[col+4]),
            gf256::from(state[col+8]),
            gf256::from(state[col+12]),
        ];

        state[col] = ((a[0] * gf256::from(0x0e)) + (a[1] * gf256::from(0x0b)) + (a[2] * gf256::from(0x0d)) + (a[3] * gf256::from(0x09))).into();
        state[col + 4] = ((a[0] * gf256::from(0x09)) + (a[1] * gf256::from(0x0e)) + (a[2] * gf256::from(0x0b)) + (a[3] * gf256::from(0x0d))).into();
        state[col + 8] = ((a[0] * gf256::from(0x0d)) + (a[1] * gf256::from(0x09)) + (a[2] * gf256::from(0x0e) + (a[3] * gf256::from(0x0b)))).into();
        state[col + 12] = ((a[0] * gf256::from(0x0b)) + (a[1] * gf256::from(0x0d)) + (a[2] * gf256::from(0x09)) + (a[3] * gf256::from(0x0e))).into();
    }
}
