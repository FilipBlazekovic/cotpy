#ifndef COTPY_H
#define COTPY_H

#include <stdbool.h>
#include <stdlib.h>

#include "cotpy_types.h"

/*
 * Parses an otpauth uri instance into a cotpy_token
 * structure which can be used for subsequent function calls.
 */
cotpy_token *from_uri(const char *uri);

/* Constructs an otpauth uri string from a provided cotpy_token structure. */
char *to_uri(const cotpy_token *token);

/*
 * Returns TOTP token with SHA512 algorithm, 6-digit OTP,
 * 30s period and 64-bytes of random data for the secret.
 */
cotpy_token *generate_token(void);

/*
 * Returns the calculated OTP value based on the params in the provided token.
 * For TOTP tokens "period" field and current time in seconds since epoch will
 * be used to generate a counter for OTP calculation, for HOTP tokens the value
 * in "counter" field will be used.
 */
char *get_otp(const cotpy_token *token);

/*
 * Validates the provided OTP against one calculated from the provided token.
 * Param "max_backward_drift" (>=0) determines how many previous counter values
 * should also be checked during validation to account for issues in time
 * synchronization between devices or lag due to network transport.
 */
bool validate_otp(const cotpy_token *token, const char *otp, uint32_t max_backward_drift);

/* The following functions are an alternative way to use the library
 * by not relying on "cotp_token" structure but instead providing the
 * params manually.
 */

char *get_hotp(
    const unsigned char *secret,
    size_t secret_length,
    cotpy_algorithm algorithm,
    cotpy_digits digits,
    uint64_t counter
);

char *get_totp(
    const unsigned char *secret,
    size_t secret_length,
    cotpy_algorithm algorithm,
    cotpy_digits digits,
    uint32_t period
);

char *get_totp_for_time(
    const unsigned char *secret,
    size_t secret_length,
    cotpy_algorithm algorithm,
    cotpy_digits digits,
    uint32_t period,
    uint64_t time
);

bool validate_hotp(
    const unsigned char *secret,
    size_t secret_length,
    cotpy_algorithm algorithm,
    cotpy_digits digits,
    uint64_t counter,
    const char *otp,
    uint32_t max_backward_drift
);

bool validate_totp(
    const unsigned char *secret,
    size_t secret_length,
    cotpy_algorithm algorithm,
    cotpy_digits digits,
    uint32_t period,
    const char *otp,
    uint32_t max_backward_drift
);

#endif //COTPY_H
