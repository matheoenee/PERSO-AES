#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes_functions.h"
#include "aes_crypto.h"


int main() {
    // AES 128-bit key
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    // Encrypt the file "test.txt" into "test_encrypt.txt"
    printf("Encrypting 'JDA_VRI_Rijndael_2002.pdf' into 'test_encrypt.txt'...\n");
    aes_cbc_cipher("JDA_VRI_Rijndael_2002.pdf", "Rijndael.encrypt", key, 10, 4);

    // Decrypt the file "test_encrypt.txt" into "test_decrypt.txt"
    printf("Decrypting 'Rijndael.encrypt' into 'test_decrypt.txt'...\n");
    aes_cbc_inv_cipher("Rijndael.encrypt", "Rijndael_decrypt.pdf", key, 10, 4);

    printf("Encryption and decryption completed.\n");

    return 0;
}
