#ifndef GF256_H
#define GF256_H

#include <stdint.h>
 
// Multiplication in GF(256) with m(x) = x^8 + x^4 + x^3 + x + 1
uint8_t gf256_mul(uint8_t a, uint8_t b);

#endif