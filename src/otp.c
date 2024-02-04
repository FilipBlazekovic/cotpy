#include "otp.h"

const size_t COTPY_MAX_HMAC_SIZE = 64;

const int COTPY_DIGITS_POWER[] = {
    1,
    10,
    100,
    1000,
    10000,
    100000,
    1000000,
    10000000,
    100000000
};

static bool is_little_endian(void)
{
    int n = 1;
    if (*(char *) &n == 1)
        return true;
    return false;
}

static void to_big_endian(uint64_t value, void *vdest)
{
    uint8_t *bytes = (uint8_t *) vdest;
    bytes[0] = value >> 56;
    bytes[1] = value >> 48;
    bytes[2] = value >> 40;
    bytes[3] = value >> 32;
    bytes[4] = value >> 24;
    bytes[5] = value >> 16;
    bytes[6] = value >> 8;
    bytes[7] = value;
}

static void secure_free(void *pbytes, size_t num_bytes)
{
    if (pbytes != NULL)
    {
        memset(pbytes, '\0', num_bytes);
        free(pbytes);
    }
}

static char *truncate_hmac(const unsigned char *hmac, const size_t hmac_length, const uint32_t digits)
{
    // Retrieving the offset where otp of interest starts
    int offset = hmac[hmac_length - 1] & 0xf;

    // Collecting 4 bytes from the offset into a number
    int binary = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8) |
                 (hmac[offset + 3] & 0xff);

    // Converting the binary number into a decimal otp of requested length
    int otp = binary % COTPY_DIGITS_POWER[digits];

    char *result = calloc(1, digits + 1);
    if (digits == 6)
    {
        sprintf(result, "%06d", otp);
        return result;
    }

    sprintf(result, "%08d", otp);
    return result;
}

char *cotpy_calculate_otp(
    const unsigned char *secret,
    const size_t secret_length,
    const EVP_MD *algorithm,
    const uint32_t digits,
    const uint64_t counter
)
{
    unsigned int hmac_length = -1;
    unsigned char *hmac = malloc(COTPY_MAX_HMAC_SIZE);
    unsigned char counter_bytes[sizeof(counter)];

    if (is_little_endian())
        to_big_endian(counter, &counter_bytes);
    else
        memcpy(counter_bytes, &counter, sizeof(counter));

    if (HMAC(
        algorithm,
        secret,
        (int) secret_length,
        counter_bytes,
        sizeof(counter),
        hmac,
        &hmac_length) == NULL)
    {
        free(hmac);
        return NULL;
    }

    char *otp = truncate_hmac(hmac, hmac_length, digits);
    secure_free(hmac, hmac_length);
    return otp;
}

bool cotpy_validate_otp(
    const unsigned char *secret,
    const size_t secret_length,
    const EVP_MD *algorithm,
    const uint32_t digits,
    uint64_t counter,
    const char *otp,
    const uint32_t max_backward_drift
)
{
    bool status = false;

    if (strlen(otp) != digits)
        return status;

    unsigned int hmac_length = -1;
    unsigned char *hmac = malloc(COTPY_MAX_HMAC_SIZE);

    for (int backward_drift = 0; backward_drift <= max_backward_drift; backward_drift++)
    {
        counter -= backward_drift;
        unsigned char counter_bytes[sizeof(counter)];

        if (is_little_endian())
            to_big_endian(counter, &counter_bytes);
        else
            memcpy(counter_bytes, &counter, sizeof(counter));

        if (HMAC(
            algorithm,
            secret,
            (int) secret_length,
            counter_bytes,
            sizeof(counter),
            hmac,
            &hmac_length) == NULL)
        {
            free(hmac);
            return status;
        }

        char *current_otp = truncate_hmac(hmac, hmac_length, digits);

        if (memcmp(current_otp, otp, digits) == 0)
        {
            status = true;
            secure_free(current_otp, strlen(current_otp));
            break;
        }
        secure_free(current_otp, strlen(current_otp));
    }

    secure_free(hmac, hmac_length);
    return status;
}
