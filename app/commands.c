#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sysexits.h>

#include "bencode.h"

int decode(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    const char *encoded_str = argv[0];
    BencodedValue *value = decode_bencoded_bytes((uint8_t *)encoded_str, (uint8_t *)encoded_str + strlen(encoded_str));
    if (!value) return EX_DATAERR;
    print_bencoded_value(value, (BencodedPrintConfig) {0});
    printf("\n");
    free_bencoded_value(value);
    return EX_OK;
}
