#include <openssl/rand.h>

#include "cotpy.h"
#include "otpauth.h"
#include "otp.h"

cotpy_token *from_uri(const char *uri)
{
    return cotpy_parse_otpauth_uri(uri);
}

char *to_uri(const cotpy_token *token)
{
    return cotpy_generate_otpauth_uri(token);
}

cotpy_token *generate_token(void)
{
    size_t num_random_bytes = 64;
    unsigned char *random_bytes = malloc(num_random_bytes);
    if (RAND_bytes(random_bytes, (int) num_random_bytes) != 1)
    {
        free(random_bytes);
        return NULL;
    }

    cotpy_token *token = calloc(1, sizeof(cotpy_token));
    token->protocol = COTPY_TOTP;
    token->algorithm = COTPY_SHA512;
    token->digits = COTPY_6;
    token->period = 30;

    memcpy(token->secret, random_bytes, num_random_bytes);
    token->secret_length = num_random_bytes;

    memset(random_bytes, '\0', num_random_bytes);
    free(random_bytes);
    return token;
}

char *get_otp(const cotpy_token *token)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (token->algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (token->algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    if (token->protocol == COTPY_HOTP)
    {
        return cotpy_calculate_otp(
            token->secret,
            token->secret_length,
            hash_algorithm,
            (token->digits == COTPY_6) ? 6 : 8,
            token->counter
        );
    }

    uint64_t counter = (uint64_t) (time(NULL) / token->period);
    return cotpy_calculate_otp(
        token->secret,
        token->secret_length,
        hash_algorithm,
        (token->digits == COTPY_6) ? 6 : 8,
        counter
    );
}

bool validate_otp(const cotpy_token *token, const char *otp, const uint32_t max_backward_drift)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (token->algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (token->algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    if (token->protocol == COTPY_HOTP)
    {
        return cotpy_validate_otp(
            token->secret,
            token->secret_length,
            hash_algorithm,
            (token->digits == COTPY_6) ? 6 : 8,
            token->counter,
            otp,
            max_backward_drift
        );
    }

    uint64_t counter = (uint64_t) (time(NULL) / token->period);
    return cotpy_validate_otp(
        token->secret,
        token->secret_length,
        hash_algorithm,
        (token->digits == COTPY_6) ? 6 : 8,
        counter,
        otp,
        max_backward_drift
    );
}

char *get_hotp(
    const unsigned char *secret,
    const size_t secret_length,
    const cotpy_algorithm algorithm,
    const cotpy_digits digits,
    const uint64_t counter
)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    return cotpy_calculate_otp(
        secret,
        secret_length,
        hash_algorithm,
        (digits == COTPY_6) ? 6 : 8,
        counter
    );
}

char *get_totp(
    const unsigned char *secret,
    const size_t secret_length,
    const cotpy_algorithm algorithm,
    const cotpy_digits digits,
    const uint32_t period
)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    uint64_t counter = (uint64_t) (time(NULL) / period);
    return cotpy_calculate_otp(
        secret,
        secret_length,
        hash_algorithm,
        (digits == COTPY_6) ? 6 : 8,
        counter
    );
}

char *get_totp_for_time(
    const unsigned char *secret,
    const size_t secret_length,
    const cotpy_algorithm algorithm,
    const cotpy_digits digits,
    const uint32_t period,
    const uint64_t time
)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    uint64_t counter = (uint64_t) (time / period);
    return cotpy_calculate_otp(
        secret,
        secret_length,
        hash_algorithm,
        (digits == COTPY_6) ? 6 : 8,
        counter
    );
}

bool validate_hotp(
    const unsigned char *secret,
    const size_t secret_length,
    const cotpy_algorithm algorithm,
    const cotpy_digits digits,
    uint64_t counter,
    const char *otp,
    const uint32_t max_backward_drift
)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    return cotpy_validate_otp(
        secret,
        secret_length,
        hash_algorithm,
        (digits == COTPY_6) ? 6 : 8,
        counter,
        otp,
        max_backward_drift
    );
}

bool validate_totp(
    const unsigned char *secret,
    const size_t secret_length,
    const cotpy_algorithm algorithm,
    const cotpy_digits digits,
    uint32_t period,
    const char *otp,
    const uint32_t max_backward_drift
)
{
    EVP_MD *hash_algorithm = (EVP_MD *) EVP_sha1();
    if (algorithm == COTPY_SHA256)
        hash_algorithm = (EVP_MD *) EVP_sha256();
    else if (algorithm == COTPY_SHA512)
        hash_algorithm = (EVP_MD *) EVP_sha512();

    uint64_t counter = (uint64_t) (time(NULL) / period);
    return cotpy_validate_otp(
        secret,
        secret_length,
        hash_algorithm,
        (digits == COTPY_6) ? 6 : 8,
        counter,
        otp,
        max_backward_drift
    );
}
