#include "otpauth.h"

static char *encode_value(const char *value)
{
    size_t length = (value == NULL) ? 0 : strlen(value);
    if (length == 0)
        return NULL;

    char *encoded_value = calloc(1, length * 3 + 1);
    uri_encode(value, length, encoded_value);
    return encoded_value;
}

static char *decode_value(const char *encoded_value)
{
    size_t length = (encoded_value == NULL) ? 0 : strlen(encoded_value);
    if (length == 0)
        return NULL;

    char *value = calloc(1, length + 1);
    uri_decode(encoded_value, length, value);
    return value;
}

static size_t parse_account(cotpy_token *token, char *uri)
{
    int index = -1;
    for (int i = 0; i < strlen(uri); i++)
    {
        if (uri[i] == '?')
        {
            index = i;
            break;
        }
    }

    if (index == -1)
        return 0;

    char buffer[COTPY_BUFFER_SIZE];
    memcpy(buffer, uri, index);
    memset(&buffer[index], 0, 1);

    size_t offset = strlen(buffer) + 1;
    char *issuer_or_account = strtok(buffer, ":");
    char *account = strtok(NULL, ":");

    if (account == NULL)
    {
        memcpy(
            token->account,
            issuer_or_account,
            (strlen(issuer_or_account) < MAX_ACCOUNT_LENGTH) ? strlen(issuer_or_account) : MAX_ACCOUNT_LENGTH - 1
        );
        return offset;
    }
    memcpy(
        token->issuer,
        issuer_or_account,
        (strlen(issuer_or_account) < MAX_ISSUER_LENGTH) ? strlen(issuer_or_account) : MAX_ISSUER_LENGTH - 1
    );
    memcpy(
        token->account,
        account,
        (strlen(account) < MAX_ACCOUNT_LENGTH) ? strlen(account) : MAX_ACCOUNT_LENGTH - 1
    );

    return offset;
}

static cotpy_param_name parse_param(cotpy_token *token, char *param)
{
    char *value = strchr(param, '=');
    if (value == NULL)
        return COTPY_PARAM_UNKNOWN;

    size_t length = strlen(param);
    value++;

    if (length >= 6 && strncmp(param, "secret", 6) == 0)
    {
        unsigned char *secret = NULL;
        size_t secret_length = from_base32(value, &secret);
        if (secret == NULL || secret_length > MAX_SECRET_LENGTH)
            return COTPY_PARAM_UNKNOWN;

        memcpy(token->secret, secret, secret_length);
        token->secret_length = secret_length;
        return COTPY_PARAM_SECRET;
    }

    if (length >= 6 && strncmp(param, "issuer", 6) == 0)
    {
        memcpy(
            token->issuer,
            value,
            (strlen(value) < MAX_ISSUER_LENGTH) ? strlen(value) : MAX_ISSUER_LENGTH - 1
        );
        return COTPY_PARAM_ISSUER;
    }

    if (length >= 9 && strncmp(param, "algorithm", 9) == 0)
    {
        if (strlen(value) == 6 && strncmp(value, "SHA256", 6) == 0)
        {
            token->algorithm = COTPY_SHA256;
            return COTPY_PARAM_ALGORITHM;
        }
        if (strlen(value) == 6 && strncmp(value, "SHA512", 6) == 0)
        {
            token->algorithm = COTPY_SHA512;
            return COTPY_PARAM_ALGORITHM;
        }
        token->algorithm = COTPY_SHA1;
        return COTPY_PARAM_ALGORITHM;
    }

    if (length >= 6 && strncmp(param, "digits", 6) == 0)
    {
        int converted_value = (uint8_t) strtol(value, NULL, 10);
        if (converted_value == 6)
        {
            token->digits = COTPY_6;
            return COTPY_PARAM_DIGITS;
        }
        if (converted_value == 8)
        {
            token->digits = COTPY_8;
            return COTPY_PARAM_DIGITS;
        }
        return COTPY_PARAM_UNKNOWN;
    }

    if (length >= 6 && strncmp(param, "period", 6) == 0)
    {
        token->period = (uint32_t) strtol(value, NULL, 10);
        return COTPY_PARAM_PERIOD;
    }

    if (length >= 7 && strncmp(param, "counter", 7) == 0)
    {
        token->counter = (uint64_t) strtol(value, NULL, 10);
        return COTPY_PARAM_COUNTER;
    }

    return COTPY_PARAM_UNKNOWN;
}

static size_t write_numeric_param(const cotpy_token *token, const cotpy_param_name param, char *buffer, size_t index)
{
    uint64_t value;
    switch (param)
    {
        case COTPY_PARAM_DIGITS:
            value = token->digits == COTPY_6 ? 6 : 8;
            memcpy(&buffer[index], "&digits=", 8);
            index += 8;
            break;
        case COTPY_PARAM_PERIOD:
            value = token->period;
            memcpy(&buffer[index], "&period=", 8);
            index += 8;
            break;
        default:
            value = token->counter;
            memcpy(&buffer[index], "&counter=", 9);
            index += 9;
    }

    int value_length = snprintf(NULL, 0, "%lu", value);
    char *value_string = malloc(value_length + 1);
    snprintf(value_string, value_length + 1, "%ld", value);
    memcpy(&buffer[index], value_string, value_length);
    index += value_length;
    free(value_string);
    return index;
}

cotpy_token *cotpy_parse_otpauth_uri(const char *otpauth_uri)
{
    char *uri = decode_value(otpauth_uri);
    if (uri == NULL || strlen(uri) < COTPY_PROTOCOL_STRING_LENGTH)
    {
        free(uri);
        return NULL;
    }

    cotpy_token *token = calloc(1, sizeof(cotpy_token));
    token->algorithm = COTPY_SHA1;
    token->digits = COTPY_6;

    if (strncmp(uri, COTPY_PROTOCOL_STRING_HOTP, COTPY_PROTOCOL_STRING_LENGTH) == 0)
    {
        token->protocol = COTPY_HOTP;
    }
    else if (strncmp(uri, COTPY_PROTOCOL_STRING_TOTP, COTPY_PROTOCOL_STRING_LENGTH) == 0)
    {
        token->protocol = COTPY_TOTP;
        token->period = 30;
    }
    else
    {
        free(uri);
        free(token);
        return NULL;
    }

    size_t uri_without_protocol_length = strlen(uri) - COTPY_PROTOCOL_STRING_LENGTH;
    char uri_without_protocol[uri_without_protocol_length + 1];
    uri_without_protocol[uri_without_protocol_length] = '\0';
    memcpy(uri_without_protocol, uri + COTPY_PROTOCOL_STRING_LENGTH, uri_without_protocol_length);

    size_t offset = parse_account(token, uri_without_protocol);
    if (offset == 0)
    {
        free(uri);
        free(token);
        return NULL;
    }

    size_t params_length = uri_without_protocol_length - offset;
    char params[params_length + 1];
    params[params_length] = '\0';
    strncpy(params, uri_without_protocol + offset, params_length);

    bool secret_found = false;

    char *param = strtok(params, "&");
    do
    {
        if (parse_param(token, param) == COTPY_PARAM_SECRET)
            secret_found = true;
        param = strtok(NULL, "&");
    }
    while (param != NULL);

    if (!secret_found)
    {
        free(uri);
        free(token);
        return NULL;
    }

    free(uri);
    return token;
}

char *cotpy_generate_otpauth_uri(const cotpy_token *token)
{
    if (token == NULL)
        return NULL;

    char *secret_encoded = NULL;
    to_base32(token->secret, token->secret_length, &secret_encoded);
    if (secret_encoded == NULL)
        return NULL;

    size_t index = 0;
    char *buffer = calloc(1, COTPY_BUFFER_SIZE);

    if (token->protocol == COTPY_HOTP)
        memcpy(&buffer[index], COTPY_PROTOCOL_STRING_HOTP, COTPY_PROTOCOL_STRING_LENGTH);
    else
        memcpy(&buffer[index], COTPY_PROTOCOL_STRING_TOTP, COTPY_PROTOCOL_STRING_LENGTH);

    index += COTPY_PROTOCOL_STRING_LENGTH;

    char *encoded_issuer = strlen(token->issuer) == 0 ? NULL : encode_value(token->issuer);
    char *encoded_account = strlen(token->account) == 0 ? NULL : encode_value(token->account);

    size_t issuer_length = encoded_issuer == NULL ? 0 : strlen(encoded_issuer);
    size_t account_length = encoded_account == NULL ? 0 : strlen(encoded_account);

    if (issuer_length > 0)
    {
        memcpy(&buffer[index], encoded_issuer, issuer_length);
        index += issuer_length;
        memset(&buffer[index], ':', 1);
        index += 1;
        memcpy(&buffer[index], encoded_account, account_length);
        index += account_length;
    }
    else if (account_length > 0)
    {
        memcpy(&buffer[index], encoded_account, account_length);
        index += account_length;
    }

    memcpy(&buffer[index], "?secret=", 8);
    index += 8;
    size_t secret_length = strlen(secret_encoded);
    memcpy(&buffer[index], secret_encoded, secret_length);
    index += secret_length;
    free(secret_encoded);

    memcpy(&buffer[index], "&algorithm=", 11);
    index += 11;

    switch (token->algorithm)
    {
        case COTPY_SHA512:
            memcpy(&buffer[index], "SHA512", 6);
            index += 6;
            break;
        case COTPY_SHA256:
            memcpy(&buffer[index], "SHA256", 6);
            index += 6;
            break;
        default:
            memcpy(&buffer[index], "SHA1", 4);
            index += 4;
    }

    index = write_numeric_param(token, COTPY_PARAM_DIGITS, buffer, index);

    if (token->protocol == COTPY_HOTP)
        index = write_numeric_param(token, COTPY_PARAM_COUNTER, buffer, index);
    else
        index = write_numeric_param(token, COTPY_PARAM_PERIOD, buffer, index);

    if (issuer_length > 0)
    {
        memcpy(&buffer[index], "&issuer=", 8);
        index += 8;
        memcpy(&buffer[index], encoded_issuer, issuer_length);
    }

    size_t buffer_length = strlen(buffer);
    char *otpauth_uri = calloc(1, buffer_length + 1);
    memcpy(otpauth_uri, buffer, buffer_length);

    free(buffer);
    free(encoded_issuer);
    free(encoded_account);

    return otpauth_uri;
}
