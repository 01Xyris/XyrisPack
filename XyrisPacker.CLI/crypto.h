// crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define KEY_LENGTH 6

void generate_random(char* buffer, int length);
void xor_encrypt(unsigned char* data, size_t data_len, const char* key, size_t key_len);

#endif // CRYPTO_H