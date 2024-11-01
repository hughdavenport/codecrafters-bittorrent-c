#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>

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
