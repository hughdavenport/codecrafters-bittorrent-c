#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sysexits.h>
#include <errno.h>

#define SHA1_IMPLEMENTATION
#include "sha1.h"

#define URL_IMPLEMENTATION
#include "url.h"

#define BENCODE_IMPLEMENTATION
#include "bencode.h"

int info_file(const char *fname) {
    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(fname);
    if (!decoded) goto end;
    if (decoded->type != DICT) goto end;
    BencodedDict *dict = (BencodedDict *)decoded->data;

    BencodedValue *announce = bencoded_dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;
    printf("Tracker URL: ");
    print_bencoded_value(announce, (BencodedPrintConfig) {.noquotes = true, .newline=true});

    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;
    printf("Length: ");
    print_bencoded_value(length, (BencodedPrintConfig) {.newline = true});

    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    printf("Info Hash: ");
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        printf("%02x", info_hash[idx]);
    }
    printf("\n");

    BencodedValue *piece_length = bencoded_dict_value((BencodedDict *)info->data, "piece length");
    if (!piece_length) goto end;
    if (piece_length->type != INTEGER) goto end;
    ret = EX_OK;
    printf("Piece Length: %ld\n", piece_length->size);

    BencodedValue *pieces = bencoded_dict_value((BencodedDict *)info->data, "pieces");
    if (!pieces) goto end;
    if (pieces->type != BYTES) goto end;
    printf("Piece Hashes:\n");
    for (int piece = 0; piece < pieces->size / SHA1_DIGEST_BYTE_LENGTH; piece ++) {
        for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
            printf("%02x", ((uint8_t *)pieces->data)[piece * SHA1_DIGEST_BYTE_LENGTH + idx]);
        }
        printf("\n");
    }
    printf("\n");

end:
    if (decoded) {
        free((void *)decoded->start); // Free memory allocated in decode_bencoded_file
        free_bencoded_value(decoded);
    }
    if (errno) {
        int ret = errno;
        return ret;
    }
    return ret;
}

int send_tracker_request(URL *url,
        uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        const char *peer_id,
        size_t uploaded, size_t downloaded, size_t length) {
    int sock = -1;

    sock = connect_url(url);
    if (sock == -1) return sock;

    dprintf(sock, "GET /");
    if (url->path) dprintf(sock, "%s", url->path);
    dprintf(sock, "?");
    if (url->query) dprintf(sock, "%s&", url->query);

    dprintf(sock, "info_hash=");
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        if (!is_url_print(info_hash[idx])) {
            dprintf(sock, "%%%02x", info_hash[idx]);
        } else {
            dprintf(sock, "%c", info_hash[idx]);
        }
    }

    dprintf(sock, "&peer_id=%s", peer_id);
    dprintf(sock, "&port=%d", 6881);
    dprintf(sock, "&uploaded=%lu", uploaded);
    dprintf(sock, "&downloaded=%lu", downloaded);
    dprintf(sock, "&left=%lu", length);
    dprintf(sock, "&compact=1");
    dprintf(sock, " HTTP/1.0\r\n");

    // FIXME: This should have port, but only if present
    dprintf(sock, "Host: %s\r\n", url->host);
    dprintf(sock, "User-Agent: %s\r\n", "I did this myself while coding a bittorrent client in C on codecrafters.io");
    dprintf(sock, "Accept: */*\r\n");
    dprintf(sock, "\r\n");

    return sock;
}

char *read_line(char *start, char *end, char **ret) {
    if (start >= end) return NULL;
    char *p = start;
    while (p < end && *p != '\r') p++;
    if (p >= end) {
        *ret = start;
        return p;
    }
    if (p + 1 >= end || *(p + 1) != '\n') {
        fprintf(stderr, "Expected \\n after \\r\n");
        return NULL;
    }
    *p = 0;
    *ret = start;
    return p + 2 >= end ? p + 1 : p + 2;
}

BencodedValue *read_tracker_response(int sock) {
    BencodedValue *ret = NULL;
#define BUF_SIZE 4096
    char buf[BUF_SIZE]; // FIXME: This is just on stack, and a limited size. May need to allocate if larger responses
    int len = read(sock, buf, BUF_SIZE);
    char *p = buf;
    char *line;
    char *end = buf + len;

    p = read_line(p, end, &line);
    char *space = index(line, ' ');
#define s(str) str, strlen(str)
    if (space == NULL || strncmp(line, s("HTTP/")) != 0) {
        fprintf(stderr, "Wrong protocol recieved: %s\n", line);
        goto cleanup;
    }
    if (strncmp(line + strlen("HTTP/"), s("1.")) != 0) {
        *space = 0;
        fprintf(stderr, "Wrong HTTP version %s\n", (line + strlen("HTTP/")));
        *space = ' ';
        goto cleanup;
    }
    *space = 0;
    if (strcmp(line + strlen("HTTP/1."), "0") != 0) {
        fprintf(stderr, "Different HTTP minor version %s\n", (line + strlen("HTTP/")));
    }
    *space = ' ';

    char *status = space + 1;
    while (*status == ' ') status ++;
    space = index(status, ' ');
    if (space == NULL) {
        fprintf(stderr, "Could not find status code: %s\n", line);
        goto cleanup;
    }
    *space = 0;
    if (strcmp(status, "200") != 0) {
        fprintf(stderr, "Non-OK status %s\n", status);
        *space = ' ';
        goto cleanup;
    }
    *space = ' ';

    long content_length = 0;
    // FIXME: read more?
    while (p = read_line(p, end, &line)) {
        if (*line == 0) {
            break;
        }
        char *colon = index(line, ':');
        *colon = 0;
        if (strncasecmp(line, s("Content-Length")) == 0) {
            content_length = atol(colon + 1);
            fprintf(stderr, "Content-Length: %ld\n", content_length);
        }
        *colon = ':';
    }

    if (content_length == 0) {
        fprintf(stderr, "Could not find Content-Length\n");
        // FIXME select() to find out if more to read?
    }

    if (content_length > 0 && content_length + (p - buf) > len) {
        fprintf(stderr, "Need to read %ld more bytes\n", content_length + (p - buf) - len);
        goto cleanup;
    }

    ret = decode_bencoded_bytes(p, end);

cleanup:
    // FIXME if buffers are alloc'd in future, clean them here maybe

    return ret;
}


int peers_file(const char *fname) {
    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(fname);
    if (!decoded) goto end;
    if (decoded->type != DICT) goto end;
    BencodedDict *dict = (BencodedDict *)decoded->data;
    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;

    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    BencodedValue *announce = bencoded_dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;

    URL url = {0};
    if (!parse_url((char *)announce->data,
                (char *)announce->data + announce->size,
                &url)) {
        goto end;
    }

    const char *peer_id = "AdtLtU86udGzzN5m9GDs"; // 20 byte identifier. This is random data
    int sock = send_tracker_request(&url, info_hash, peer_id, 0, 0, length->size);

    BencodedValue *response = read_tracker_response(sock);
    if (!response) goto end;
    if (response->type != DICT) goto end;
    dict = (BencodedDict *)response->data;
    BencodedValue *peers = bencoded_dict_value(dict, "peers");
    if (peers->type != BYTES) goto end;

    for (int idx; (idx + 1) * 6 <= peers->size; idx ++) {
        printf("%d.%d.%d.%d",
                ((uint8_t *)peers->data)[6 * idx + 0],
                ((uint8_t *)peers->data)[6 * idx + 1],
                ((uint8_t *)peers->data)[6 * idx + 2],
                ((uint8_t *)peers->data)[6 * idx + 3]);
        printf(":%d\n",
                256 * ((uint8_t *)peers->data)[6 * idx + 4] +
                ((uint8_t *)peers->data)[6 * idx + 5]);
    }

end:
    if (sock != -1) close(sock);
    if (decoded) {
        free((void*)decoded->start);
        free_bencoded_value(decoded);
    }
    if (response) free_bencoded_value(response); // No memory allocated here (all on stack with buf)
    if (errno) ret = errno;
    return ret;
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
    while (read_total < fsize) {
        size_t read_count = fread(data, 1, fsize, f);
        if (read_count == 0) goto end;
        read_total += read_count;
    }

    int ret = EX_DATAERR;

    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    sha1_digest(data, fsize, info_hash);
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        printf("%02x", info_hash[idx]);
    }
    printf("\n");
    ret = EX_SOFTWARE;

end:
    if (errno) {
        int ret = errno;
        if (f) fclose(f);
        return ret;
    }
    if (f) if (!fclose(f)) return errno;
    return ret;
}

int main(int argc, char* argv[]) {
	// Disable output buffering
	setbuf(stdout, NULL);
 	setbuf(stderr, NULL);

    if (argc < 3) {
        fprintf(stderr, "Usage: your_bittorrent.sh <command> <args>\n");
        fprintf(stderr, "Available subcommands:\n");
        // FIXME do this better
        fprintf(stderr, "    decode\n");
        fprintf(stderr, "    info\n");
        fprintf(stderr, "    peers\n");
        fprintf(stderr, "Available debug commands:\n");
        fprintf(stderr, "    parse\n");
        fprintf(stderr, "    hash\n");
        return EX_USAGE;
    }

    const char* command = argv[1];

    if (strcmp(command, "decode") == 0) {
        const char* encoded_str = argv[2];
        BencodedValue *value = decode_bencoded_bytes(encoded_str, encoded_str + strlen(encoded_str));
        if (!value) return EX_DATAERR;
        print_bencoded_value(value, (BencodedPrintConfig) {0});
        printf("\n");
        free_bencoded_value(value);
        return EX_OK;
    } else if (strcmp(command, "info") == 0) {
        const char* fname = argv[2];
        return info_file(fname);
    } else if (strcmp(command, "peers") == 0) {
        const char* fname = argv[2];
        return peers_file(fname);
    } else if (strcmp(command, "parse") == 0) {
        int ret = EX_OK;
        URL url = {0};
        if (!parse_url(argv[2], NULL, &url)) ret = EX_DATAERR;
        printf("scheme = %s\n", url.scheme);
        printf("user = %s\n", url.user);
        printf("pass = %s\n", url.pass);
        printf("host = %s\n", url.host);
        printf("port = %s (%d)\n", url.port, url.port_num);
        printf("path = %s\n", url.path);
        printf("query = %s\n", url.query);
        printf("fragment = %s\n", url.fragment);
        return ret;
    } else if (strcmp(command, "hash") == 0) {
        const char* fname = argv[2];
        return hash_file(fname);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return EX_USAGE;
    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
    return EX_SOFTWARE;
}
