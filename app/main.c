#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sysexits.h>

#define UNREACH \
    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);

const char *decode_bencode(const char* bencoded_value) {
    char first = bencoded_value[0];
    switch (first) {
        case '0' ... '9': {
            int length = atoi(bencoded_value);
            const char* colon_index = strchr(bencoded_value, ':');
            if (colon_index == NULL) {
                fprintf(stderr, "Invalid encoded value: %s\n", bencoded_value);
                exit(1);
            }
            const char* start = colon_index + 1;
            printf("\"%.*s\"", length, start);
            return start + length;
        }; break;

        case 'i': {
            const char *str = bencoded_value + 1;
            while (str && *str != 'e') printf("%c", *(str++));
            return str;
        }; break;

        default:
            fprintf(stderr, "Unknown bencode character %c\n", first);
            return NULL;
    }

    UNREACH
    return NULL;
}

int main(int argc, char* argv[]) {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

    if (argc < 3) {
        fprintf(stderr, "Usage: your_bittorrent.sh <command> <args>\n");
        return EX_USAGE;
    }

    const char* command = argv[1];

    if (strcmp(command, "decode") == 0) {
        const char* encoded_str = argv[2];
        int ret = decode_bencode(encoded_str) ? EX_OK : EX_DATAERR;
        if (ret == EX_OK) printf("\n");
        return ret;
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return EX_USAGE;
    }

    UNREACH
    return EX_SOFTWARE;
}
