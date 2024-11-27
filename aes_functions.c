#include "aes_functions.h"
#include "aes_utils.h"
#include "gf256.h"

#include <stdlib.h>
#include <stdio.h>

void in_to_state(uint8_t *in, uint8_t *state){
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) { 
            state[row * 4 + col] = in[col * 4 + row];
        }
    }
}

void state_to_out(uint8_t *state, uint8_t *out){
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) { 
            out[row * 4 + col] = state[col * 4 + row];
        }
    }
}

void rot_word(uint8_t *word) {
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

void sub_word(uint8_t *word) {
    for(int i = 0; i < 4; i++) {
        word[i] = S_BOX[word[i]];
    }
}

uint8_t* key_expansion(uint8_t *key, int nr, int nk) {
    int expanded_key_size = 16 * (nr + 1);  // Number of bytes (not words)
    uint8_t *w = (uint8_t *)malloc(expanded_key_size);  

    // Initialize the first Nk words with the input key
    int i = 0;
    while (i <= nk - 1) {
        for(int j = 0; j < 4; j++){
            w[i * 4 + j] = key[i * 4 + j];
        }
        i++;
    }

    uint8_t temp[4];

    // Expand the remaining words
    while (i <= 4 * nr + 3) {
        // Copy the previous word into temp
        for (int j = 0; j < 4; j++) {
            temp[j] = w[(i - 1) * 4 + j];
        }

        // Perform operations on temp
        if (i % nk == 0) {
            rot_word(temp);               // Rotate the word
            sub_word(temp);               // Substitute the word using the S-Box
            temp[0] ^= RCON[i / nk - 1];  // XOR with the round constant
        } else if (nk > 6 && i % nk == 4) {
            sub_word(temp);               // Apply SubWord only when nk > 6
        }

        // XOR temp with the word Nk positions before
        for (int j = 0; j < 4; j++) {
            w[i * 4 + j] = w[(i - nk) * 4 + j] ^ temp[j];
        }
        i++;
    }
    return w; // Return the expanded key
}


void sub_bytes(uint8_t *state) {
    for(int i = 0; i < 16; i++){
        state[i] = S_BOX[state[i]];
    }
}

void inv_sub_bytes(uint8_t *state) {
    for(int i = 0; i < 16; i++){
        state[i] = INV_S_BOX[state[i]];
    }
}

void shift_rows(uint8_t *state) {
    uint8_t tmp;
    
    //second row
    tmp = state[4];
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = tmp;

    //third row
    tmp = state[8];
    state[8] = state[10];
    state[10] = tmp;
    tmp = state[9];
    state[9] = state[11];
    state[11] = tmp;

    //fourth row
    tmp = state[12];
    state[12] = state[15];
    state[15] = state[14];
    state[14] = state[13];
    state[13] = tmp;
}

void inv_shift_rows(uint8_t *state) {
    uint8_t tmp;
    
    //second row
    tmp = state[4];
    state[4] = state[7];
    state[7] = state[6];
    state[6] = state[5];
    state[5] = tmp;

    //third row
    tmp = state[8];
    state[8] = state[10];
    state[10] = tmp;
    tmp = state[9];
    state[9] = state[11];
    state[11] = tmp;

    //fourth row
    tmp = state[12];
    state[12] = state[13];
    state[13] = state[14];
    state[14] = state[15];
    state[15] = tmp;
}

void mix_columns(uint8_t *state) {
    for(int c = 0; c < 4; c++){
        uint8_t a[4] = {
            state[c],
            state[c + 4],
            state[c + 8],
            state[c + 12]
        };
        state[c] = gf256_mul(0x02, a[0]) ^ gf256_mul(0x03, a[1]) ^ a[2] ^ a[3];
        state[c + 4] = a[0] ^ gf256_mul(0x02, a[1]) ^ gf256_mul(0x03, a[2]) ^ a[3];
        state[c + 8] = a[0] ^ a[1] ^ gf256_mul(0x02, a[2]) ^ gf256_mul(0x03, a[3]);
        state[c + 12] = gf256_mul(0x03, a[0]) ^ a[1] ^ a[2] ^ gf256_mul(0x02, a[3]);
    }
}

void inv_mix_columns(uint8_t *state) {
    for(int c = 0; c < 4; c++){
        uint8_t a[4] = {
            state[c],
            state[c + 4],
            state[c + 8],
            state[c + 12]
        };
        state[c] = gf256_mul(0x0E, a[0]) ^ gf256_mul(0x0B, a[1]) ^ gf256_mul(0x0D, a[2]) ^ gf256_mul(0x09, a[3]);
        state[c + 4] = gf256_mul(0x09, a[0]) ^ gf256_mul(0x0E, a[1]) ^ gf256_mul(0x0B, a[2]) ^ gf256_mul(0x0D, a[3]);
        state[c + 8] = gf256_mul(0x0D, a[0]) ^ gf256_mul(0x09, a[1]) ^ gf256_mul(0x0E, a[2]) ^ gf256_mul(0x0B, a[3]);
        state[c + 12] = gf256_mul(0x0B, a[0]) ^ gf256_mul(0x0D, a[1]) ^ gf256_mul(0x09, a[2]) ^ gf256_mul(0x0E, a[3]);
    }
}

void add_round_key(uint8_t *state, uint8_t *round_key) {
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++)
        {
            state[i + 4*j] ^= round_key[i*4 + j];
        }
    }
}