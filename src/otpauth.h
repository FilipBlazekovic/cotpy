#ifndef OTPAUTH_H
#define OTPAUTH_H

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <encode.h>
#include <uri_encode.h>

#include "cotpy_types.h"

typedef enum {
    COTPY_PARAM_ISSUER,
    COTPY_PARAM_ACCOUNT,
    COTPY_PARAM_SECRET,
    COTPY_PARAM_ALGORITHM,
    COTPY_PARAM_DIGITS,
    COTPY_PARAM_PERIOD,
    COTPY_PARAM_COUNTER,
    COTPY_PARAM_UNKNOWN
} cotpy_param_name;

#define COTPY_BUFFER_SIZE               1024
#define COTPY_PROTOCOL_STRING_LENGTH    15
#define COTPY_PROTOCOL_STRING_HOTP      "otpauth://hotp/"
#define COTPY_PROTOCOL_STRING_TOTP      "otpauth://totp/"

cotpy_token * cotpy_parse_otpauth_uri(const char *otpauth_uri);
char * cotpy_generate_otpauth_uri(const cotpy_token *token);

#endif //OTPAUTH_H
