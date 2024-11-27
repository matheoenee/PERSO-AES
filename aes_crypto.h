#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <stdint.h>

void cipher(uint8_t *in, uint8_t *out, uint8_t *w, int nr);

void inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w, int nr);



void aes_ecb_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk);

void aes_ecb_inv_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk);



void generate_random_iv(uint8_t *iv);

void aes_cbc_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk);

void aes_cbc_inv_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk);

#endif