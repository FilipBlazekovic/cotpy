#ifndef COTPY_TYPES_H
#define COTPY_TYPES_H

#include <stdint.h>

#define MAX_ISSUER_LENGTH  256
#define MAX_ACCOUNT_LENGTH 256
#define MAX_SECRET_LENGTH  64

typedef enum {
    COTPY_HOTP,
    COTPY_TOTP
} cotpy_protocol;

typedef enum {
    COTPY_SHA1,
    COTPY_SHA256,
    COTPY_SHA512
} cotpy_algorithm;

typedef enum {
    COTPY_6,
    COTPY_8
} cotpy_digits;

typedef struct {
    cotpy_protocol protocol;
    cotpy_algorithm algorithm;
    char issuer[MAX_ISSUER_LENGTH];
    char account[MAX_ACCOUNT_LENGTH];
    unsigned char secret[MAX_SECRET_LENGTH];
    uint8_t secret_length;
    cotpy_digits digits;
    uint32_t period;
    uint64_t counter;
} cotpy_token;

#endif //COTPY_TYPES_H
