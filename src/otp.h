#ifndef OTP_H
#define OTP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

char *cotpy_calculate_otp(
    const unsigned char *secret,
    size_t secret_length,
    const EVP_MD *algorithm,
    uint32_t digits,
    uint64_t counter
);

bool cotpy_validate_otp(
    const unsigned char *secret,
    size_t secret_length,
    const EVP_MD *algorithm,
    uint32_t digits,
    uint64_t counter,
    const char *otp,
    uint32_t max_backward_drift
);

#endif //OTP_H
