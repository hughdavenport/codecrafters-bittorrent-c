#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <ctype.h>
#include <sysexits.h>
#include <unistd.h>

#include "sha1.h"

void hexdump(uint8_t *buf, size_t len) {
    for (size_t idx = 0; idx < len; ) {
        if (idx % 16 == 0) printf("%08lx:", idx);
        if (idx % 2 == 0) printf(" ");
        printf("%02x", (uint8_t)buf[idx]);
        idx ++;
        if (idx % 16 == 0) {
            printf("  ");
            for (size_t i = 16 * ((idx / 16) - 1); i < idx; i++) {
                if (isprint(buf[i])) {
                    printf("%c", buf[i]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
            continue;
        }
    }
    if (len % 16 != 0) {
        for (size_t idx = len % 16; idx < 16; idx ++) {
            if (idx % 2 == 0) printf(" ");
            printf("  ");
        }
        printf("  ");
        for (size_t i = 16 * (len / 16); i < len; i ++) {
            if (isprint(buf[i])) {
                printf("%c", buf[i]);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

int hash_file(const char *fname) {
    FILE *f = fopen(fname, "rb");
    if (f == NULL) return EX_NOINPUT;

    if (fseek(f, 0, SEEK_END) != 0) goto end;
    long fsize = ftell(f);
    if (fsize < 0) goto end;
    if (fseek(f, 0, SEEK_SET) != 0) goto end;

    char *data = (char *)malloc(fsize);
    size_t read_total = 0;
    while (read_total < (unsigned)fsize) {
        size_t read_count = fread(data, 1, fsize, f);
        if (read_count == 0) goto end;
        read_total += read_count;
    }

    int ret = EX_DATAERR;

    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    sha1_digest((uint8_t *)data, fsize, info_hash);
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        printf("%02x", info_hash[idx]);
    }
    printf("\n");

    ret = EX_OK;
end:
    if (data) free(data);
    if (f) if (!fclose(f)) return EX_IOERR;
    return ret;
}
