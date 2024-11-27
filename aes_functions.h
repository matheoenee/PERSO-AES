#ifndef AES_FUNCTIONS_H
#define AES_FUNCTIONS_H

#include <stdint.h>

void in_to_state(uint8_t *in, uint8_t *state);

void state_to_out(uint8_t *state, uint8_t *out);

void rot_word(uint8_t *word);

void sub_word(uint8_t *word);

uint8_t* key_expansion(uint8_t *key, int nr, int nk);

void sub_bytes(uint8_t *state);

void inv_sub_bytes(uint8_t *state);

void shift_rows(uint8_t *state);

void inv_shift_rows(uint8_t *state);

void mix_columns(uint8_t *state);

void inv_mix_columns(uint8_t *state);

void add_round_key(uint8_t *state, uint8_t *round_key);

#endif