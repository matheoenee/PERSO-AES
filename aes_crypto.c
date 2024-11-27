/*****************************************************
 * Author: Matheo ENEE
 * Date: 22.11.2024
 * 
 * Description:
 * This file implements the Advanced Encryption Standard (AES)
 * as specified in FIPS PUB 197. It provides functions for 
 * encryption, decryption, and key expansion in compliance with
 * the standard requirements.
 * 
 * Compliance:
 * - This implementation follows the Federal Information 
 *   Processing Standards Publication 197 (FIPS PUB 197).
 * 
 *****************************************************/

#include "aes_crypto.h"
#include "aes_functions.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// IMPROVEMENT : Add Header with Metadata and Footer with HMAC to authenticate the metada

void cipher(uint8_t *in, uint8_t *out, uint8_t *w, int nr) {
    uint8_t state[16];  // Temporary state to hold intermediate values

    // Convert input to state array
    in_to_state(in, state);

    // Add the initial round key
    add_round_key(state, w);

    // Perform nr-1 rounds
    for (int round = 1; round < nr; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &w[round * 16]);
    }

    // Perform the final round (without MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &w[nr * 16]);

    // Convert state array to output
    state_to_out(state, out);
}

void inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w, int nr) {
    uint8_t state[16];  // Temporary state to hold intermediate values

    // Convert input to state array
    in_to_state(in, state);

    // Add the last round key
    add_round_key(state, &w[nr * 16]);

    // Perform nr-1 rounds
    for (int round = nr - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &w[round * 16]);
        inv_mix_columns(state);
    }

    // Perform the final round (without MixColumns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, w);

    // Convert state array to output
    state_to_out(state, out);
}

void aes_ecb_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk) {
    // Open the input file in binary read mode
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return;
    }

    // Open the output file in binary write mode
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return;
    }

    // Get the size of the input file (original length)
    fseek(input_file, 0, SEEK_END);
    size_t original_length = ftell(input_file);
    rewind(input_file);

    // Write the original length as metadata (8 bytes)
    fwrite(&original_length, sizeof(size_t), 1, output_file);

    // Key expansion
    uint8_t *expanded_key = key_expansion(key, nr, nk);

    // Buffer for plaintext and ciphertext
    uint8_t plaintext[16];
    uint8_t ciphertext[16];

    // Read the file block by block (16 bytes per block)
    size_t bytes_read;
    while ((bytes_read = fread(plaintext, 1, 16, input_file)) > 0) {
        // If the last block is less than 16 bytes, pad with zeros
        if (bytes_read < 16) {
            memset(plaintext + bytes_read, 0, 16 - bytes_read);
        }

        // Encrypt the block using the cipher function
        cipher(plaintext, ciphertext, expanded_key, nr);

        // Write the ciphertext block to the output file
        fwrite(ciphertext, 1, 16, output_file);
    }

    // Free the expanded key memory
    free(expanded_key);

    // Close the files
    fclose(input_file);
    fclose(output_file);
}

void aes_ecb_inv_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk) {
    // Open the input file in binary read mode
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return;
    }

    // Open the output file in binary write mode
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return;
    }

    // Read the original length from the metadata (8 bytes)
    size_t original_length;
    fread(&original_length, sizeof(size_t), 1, input_file);

    // Key expansion
    uint8_t *expanded_key = key_expansion(key, nr, nk);

    // Buffer for ciphertext and decrypted plaintext
    uint8_t ciphertext[16];
    uint8_t plaintext[16];

    // Read the file block by block (16 bytes per block)
    size_t bytes_read;
    size_t total_bytes_written = 0;
    while ((bytes_read = fread(ciphertext, 1, 16, input_file)) > 0) {
        // Ensure that the input is a full block size
        if (bytes_read < 16) {
            fprintf(stderr, "Error: Ciphertext size is not a multiple of block size\n");
            fclose(input_file);
            fclose(output_file);
            free(expanded_key);
            return;
        }

        // Decrypt the block using the inv_cipher function
        inv_cipher(ciphertext, plaintext, expanded_key, nr);

        // Determine how many bytes to write (truncate padding in the last block)
        size_t bytes_to_write = 16;
        if (total_bytes_written + bytes_to_write > original_length) {
            bytes_to_write = original_length - total_bytes_written;
        }

        // Write the truncated block to the output file
        fwrite(plaintext, 1, bytes_to_write, output_file);
        total_bytes_written += bytes_to_write;

        // Stop writing if we reach the original plaintext length
        if (total_bytes_written >= original_length) {
            break;
        }
    }

    // Free the expanded key memory
    free(expanded_key);

    // Close the files
    fclose(input_file);
    fclose(output_file);
}

// Generate a random IV (16 bytes)
void generate_random_iv(uint8_t *iv) {
    srand((unsigned)time(NULL)); // Seed the random number generator
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
}

void aes_cbc_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk) {
    // Open the input file in binary read mode
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return;
    }

    // Open the output file in binary write mode
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return;
    }

    // Get the size of the input file (original length)
    fseek(input_file, 0, SEEK_END);
    size_t original_length = ftell(input_file);
    rewind(input_file);

    // Generate a random IV
    uint8_t iv[16];
    generate_random_iv(iv);

    // Write the IV to the output file
    fwrite(iv, 1, 16, output_file);

    // Write the original length to the output file (8 bytes)
    fwrite(&original_length, sizeof(size_t), 1, output_file);

    // Key expansion
    uint8_t *expanded_key = key_expansion(key, nr, nk);

    // Buffer for plaintext, ciphertext, and previous block
    uint8_t plaintext[16], ciphertext[16], previous_block[16];

    // Initialize the previous block with the IV
    memcpy(previous_block, iv, 16);

    // Read the file block by block (16 bytes per block)
    size_t bytes_read;
    while ((bytes_read = fread(plaintext, 1, 16, input_file)) > 0) {
        // Pad the last block with zeros if necessary
        if (bytes_read < 16) {
            memset(plaintext + bytes_read, 0, 16 - bytes_read);
        }

        // XOR the plaintext with the previous block (CBC mode)
        for (int i = 0; i < 16; i++) {
            plaintext[i] ^= previous_block[i];
        }

        // Encrypt the block using the cipher function
        cipher(plaintext, ciphertext, expanded_key, nr);

        // Write the ciphertext block to the output file
        fwrite(ciphertext, 1, 16, output_file);

        // Update the previous block to the current ciphertext
        memcpy(previous_block, ciphertext, 16);
    }

    // Free the expanded key memory
    free(expanded_key);

    // Close the files
    fclose(input_file);
    fclose(output_file);
}

void aes_cbc_inv_cipher(const char *input_filename, const char *output_filename, uint8_t *key, int nr, int nk) {
    // Open the input file in binary read mode
    FILE *input_file = fopen(input_filename, "rb");
    if (!input_file) {
        perror("Error opening input file");
        return;
    }

    // Open the output file in binary write mode
    FILE *output_file = fopen(output_filename, "wb");
    if (!output_file) {
        perror("Error opening output file");
        fclose(input_file);
        return;
    }

    // Read the IV from the input file
    uint8_t iv[16];
    fread(iv, 1, 16, input_file);

    // Read the original length from the input file (8 bytes)
    size_t original_length;
    fread(&original_length, sizeof(size_t), 1, input_file);

    // Key expansion
    uint8_t *expanded_key = key_expansion(key, nr, nk);

    // Buffer for ciphertext, plaintext, and previous block
    uint8_t ciphertext[16], plaintext[16], previous_block[16];

    // Initialize the previous block with the IV
    memcpy(previous_block, iv, 16);

    // Read the file block by block (16 bytes per block)
    size_t bytes_read;
    size_t total_bytes_written = 0;
    while ((bytes_read = fread(ciphertext, 1, 16, input_file)) > 0) {
        // Decrypt the block using the inv_cipher function
        inv_cipher(ciphertext, plaintext, expanded_key, nr);

        // XOR the plaintext with the previous block (CBC mode)
        for (int i = 0; i < 16; i++) {
            plaintext[i] ^= previous_block[i];
        }

        // Update the previous block to the current ciphertext
        memcpy(previous_block, ciphertext, 16);

        // Determine how many bytes to write (truncate padding in the last block)
        size_t bytes_to_write = 16;
        if (total_bytes_written + bytes_to_write > original_length) {
            bytes_to_write = original_length - total_bytes_written;
        }

        // Write the plaintext block to the output file
        fwrite(plaintext, 1, bytes_to_write, output_file);
        total_bytes_written += bytes_to_write;

        // Stop writing if we reach the original plaintext length
        if (total_bytes_written >= original_length) {
            break;
        }
    }

    // Free the expanded key memory
    free(expanded_key);

    // Close the files
    fclose(input_file);
    fclose(output_file);
}
