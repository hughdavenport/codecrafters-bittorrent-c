#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

char* decode_bencode(const char* bencoded_value) {
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
            char* decoded_str = (char*)malloc(length + 3);
            strncpy(decoded_str + 1, start, length);
            decoded_str[0] = '"';
            decoded_str[length + 1] = '"';
            decoded_str[length + 2] = '\0';
            return decoded_str;
        }; break;

        case 'i': {
            int idx = 1;
            while (bencoded_value[idx] && bencoded_value[idx] != 'e') idx ++;
            char *decoded_str = (char*)malloc(idx);
            strncpy(decoded_str, &bencoded_value[1], idx - 1);
            decoded_str[idx - 1] = '\0';
            return decoded_str;
        }; break;

        default:
            fprintf(stderr, "Unknown bencode character %c\n", first);
            exit(1);
    }
}

int main(int argc, char* argv[]) {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

    if (argc < 3) {
        fprintf(stderr, "Usage: your_bittorrent.sh <command> <args>\n");
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "decode") == 0) {
        const char* encoded_str = argv[2];
        char* decoded_str = decode_bencode(encoded_str);
        printf("%s\n", decoded_str);
        free(decoded_str);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}
