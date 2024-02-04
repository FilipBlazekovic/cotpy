cotpy
=====

Library for generating one-time passwords (OTPs).  
Supports generation of OTP tokens, calculation and validation of OTP codes.

Supports HOTP protocol, based on [RFC 4226](https://www.rfc-editor.org/rfc/pdfrfc/rfc4226.txt.pdf).  
Supports TOTP protocol, based on [RFC 6238](https://www.rfc-editor.org/rfc/pdfrfc/rfc6238.txt.pdf).  

Dependencies:
- OpenSSL
- [libencode](https://github.com/FilipBlazekovic/encode) - build instructions in README.md
- [liburi_encode](https://github.com/dnmfarrell/URI-Encode-C) - build instructions in README.md

Building:

```
git clone git@github.com:FilipBlazekovic/cotpy.git

cd cotpy

cmake -B build -S .

cmake --build build --target cotpy

sudo cmake --install build
```
```
To change install location of cotpy.h, cotpy_types.h and libcotpy.a change the following two properties in CMakeLists.txt:

set(HEADERS_DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
set(LIBRARY_DESTINATION ${CMAKE_INSTALL_LIBDIR})
```

Usage:
```
#include <cotpy.h>

// Constructing a token by parsing otpauth uri
// -------------------------------------------
const char *otpauth_uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
cotpy_token *token = from_uri(otpauth_uri);
if (token != NULL)
{
    /* success */
}

// Constructing an otpauth uri from a token
// ----------------------------------------
char *otpauth_uri = to_uri(token);
if (otpauth_uri != NULL)
{
    /* success */
}

// Generating a random TOTP token with 6-digit OTP, 30s period, and SHA512 digest algorithm
// ----------------------------------------------------------------------------------------
cotpy_token *token = generate_token();
if (token != NULL)
{
    /* success */
}

// Manually generating a token structure
// -------------------------------------
const char *issuer  = "Example";
const char *account = "Alice";
const char *secret  = "01234567890123456789";

cotpy_token *token  = calloc(1, sizeof(cotpy_token));
token->protocol     = COTPY_TOTP;
token->algorithm    = COTPY_SHA1;
token->digits       = COTPY_6;
token->period       = 30;

token->secret_length = strlen(secret);
memcpy(token->secret, secret, token->secret_length);

memcpy(
    token->issuer,
    issuer,
    strlen(issuer) < MAX_ISSUER_LENGTH ? strlen(issuer) : MAX_ISSUER_LENGTH - 1
);

memcpy(
    token->account,
    account,
    strlen(account) < MAX_ACCOUNT_LENGTH ? strlen(account) : MAX_ACCOUNT_LENGTH - 1
);

// Calculating OTP
// ---------------
char *otp = get_otp(token);
if (otp != NULL)
{
    /* success */
}

// Validating OTP
// --------------
bool valid = validate_otp(token, "574874", 0);


// Utility functions
// -----------------
// It's also possible to use the library without using cotpy_token structure
// by calculating and validating OTP codes using utility functions below:

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
```