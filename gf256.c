#include <stdint.h>

// Multiplication in GF(256) with m(x) = x^8 + x^4 + x^3 + x + 1
uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0; // Product
    uint8_t msb;

    // Perform bitwise multiplication
    for (int i = 0; i < 8; i++) {
        // Check if the lowest bit of b is set
        if (b & 1) {
            p ^= a; // Add a to the product (XOR in GF(256))
        }

        // Prepare for the next bit shift
        msb = a & 0x80; // Check if the MSB of a is set
        a <<= 1;          // Shift a to the left by 1

        // If msb is set, reduce a modulo m(x)
        if (msb) {
            a ^= 0x1B; // m(x) = x^8 + x^4 + x^3 + x + 1 corresponds to 0x11B
        }

        b >>= 1; // Shift b to the right by 1
    }

    return p;
}
