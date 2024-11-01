#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sysexits.h>
#include <errno.h>

#include <time.h>

#define SHA1_IMPLEMENTATION
#include "sha1.h"

#define URL_IMPLEMENTATION
#include "url.h"

#define BENCODE_IMPLEMENTATION
#include "bencode.h"

#define s(str) str, strlen(str)

// 20 byte identifier. This is random data
#define PEER_ID "AdtLtU86udGzzN5m9GDs"
#define PEER_ID_SIZE 20
#define HANDSHAKE_PROTOCOL "BitTorrent protocol"
#define HANDSHAKE_SIZE 68
#define RESERVED_SIZE 8

// 2^14 (16 kiB)
#define BLOCK_SIZE 16384

typedef enum:uint8_t {
    CHOKE,
    UNCHOKE,
    INTERESTED,
    NOT_INTERESTED,
    HAVE,
    BITFIELD,
    REQUEST,
    PIECE,
    CANCEL
} PeerMessageType;

typedef struct {
    uint32_t index;
    uint32_t begin;
    uint32_t length;
} RequestPayload;

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

    dprintf(sock, "&peer_id=%s", PEER_ID);
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
    while ((p = read_line(p, end, &line))) {
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

    ret = EX_UNAVAILABLE;
    int sock = send_tracker_request(&url, info_hash, 0, 0, length->size);
    if (sock == -1) goto end;

    ret = EX_PROTOCOL;
    BencodedValue *response = read_tracker_response(sock);
    if (!response) goto end;
    if (response->type != DICT) goto end;
    dict = (BencodedDict *)response->data;
    BencodedValue *peers = bencoded_dict_value(dict, "peers");
    if (peers->type != BYTES) goto end;
    if (peers->size % 6 != 0) goto end;

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

    ret = EX_OK;
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

    ret = EX_OK;
end:
    if (errno) {
        int ret = errno;
        if (f) fclose(f);
        return ret;
    }
    if (f) if (!fclose(f)) return errno;
    return ret;
}

// Enough space for xxx.xxx.xxx.xxx:xxxxx\0
#define PEER_STRING_SIZE 23
int random_peer(BencodedDict *dict,
        uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        char peer[PEER_STRING_SIZE]) {
    int ret = EX_DATAERR;
    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;

    BencodedValue *announce = bencoded_dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;

    URL url = {0};
    if (!parse_url((char *)announce->data,
                (char *)announce->data + announce->size,
                &url)) {
        goto end;
    }

    ret = EX_UNAVAILABLE;
    int sock = send_tracker_request(&url, info_hash, 0, 0, length->size);
    if (sock == -1) goto end;

    ret = EX_PROTOCOL;
    BencodedValue *response = read_tracker_response(sock);
    if (!response) goto end;
    if (response->type != DICT) goto end;
    dict = (BencodedDict *)response->data;
    BencodedValue *peers = bencoded_dict_value(dict, "peers");
    if (peers->type != BYTES) goto end;
    if (peers->size % 6 != 0) goto end;

    srand(time(NULL));
    int idx = random() % (peers->size / 6);
    if (snprintf(peer, PEER_STRING_SIZE, "%d.%d.%d.%d:%d",
            ((uint8_t *)peers->data)[6 * idx + 0],
            ((uint8_t *)peers->data)[6 * idx + 1],
            ((uint8_t *)peers->data)[6 * idx + 2],
            ((uint8_t *)peers->data)[6 * idx + 3],
            256 * ((uint8_t *)peers->data)[6 * idx + 4] +
            ((uint8_t *)peers->data)[6 * idx + 5]) > PEER_STRING_SIZE) {
        // FIXME This may signify IPv6
        fprintf(stderr, "%s:%d: UNREACHABLE", __FILE__, __LINE__);
        ret = EX_SOFTWARE;
    } else {
        ret = EX_OK;
    }

end:
    if (sock != -1) close(sock);
    if (response) free_bencoded_value(response); // No memory allocated here (all on stack with buf)
    if (errno) ret = errno;
    return ret;
}

int connect_peer(const char *host, const char *port) {
    struct addrinfo hints = {0};
    struct addrinfo *result, *rp = NULL;
    int ret = -1;
    size_t len;
    ssize_t nread;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return ret;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        ret = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (ret == -1)
            continue;

        if (connect(ret, rp->ai_addr, rp->ai_addrlen) == 0)
            break; // Success

        close(ret);
        ret = -1;
    }

    freeaddrinfo(result);

    return ret; // Either -1, or a file descriptor of a connected socket
}

void hexdump(uint8_t *buf, size_t len) {
    for (int idx = 0; idx < len; ) {
        if (idx % 16 == 0) printf("%08x:", idx);
        if (idx % 2 == 0) printf(" ");
        printf("%02x", (uint8_t)buf[idx]);
        idx ++;
        if (idx % 16 == 0) {
            printf("  ");
            for (int i = 16 * ((idx / 16) - 1); i < idx; i++) {
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
}

int handshake_peer(const char *host,
        const char *port,
        const uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        uint8_t response[HANDSHAKE_SIZE]) {
    int sock = connect_peer(host, port);
    if (sock == -1) return -1;

    int len = 0;
    len += dprintf(sock, "%c", (char)strlen(HANDSHAKE_PROTOCOL));
    len += dprintf(sock, HANDSHAKE_PROTOCOL);
    len += dprintf(sock, "%c%c%c%c", 0, 0, 0, 0);
    len += dprintf(sock, "%c%c%c%c", 0, 0, 0, 0);
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        len += dprintf(sock, "%c", info_hash[idx]);
    }
    len += dprintf(sock, "%s", PEER_ID);
    fprintf(stderr, "wrote %d bytes.\n", len);
    if (len != HANDSHAKE_SIZE) goto error;

    len = read(sock, response, HANDSHAKE_SIZE);
    fprintf(stderr, "read %d bytes.\n", len);
    if (len != HANDSHAKE_SIZE) goto error;

    if (response[0] != strlen(HANDSHAKE_PROTOCOL)) goto error;
    if (strncmp(response + 1, HANDSHAKE_PROTOCOL, response[0]) != 0) goto error;
    uint8_t *reserved = response + response[0] + 1;
    for (int idx = 0; idx < RESERVED_SIZE; idx ++) {
        if (reserved[idx] != 0) {
            fprintf(stderr, "WARN: reserved[%d] = 0x%02x\n", idx, reserved[idx]);
        }
    }
    // FIXME: work out what reserved bits mean what extension
    if (memcmp(reserved + RESERVED_SIZE, info_hash, SHA1_DIGEST_BYTE_LENGTH) != 0) {
        fprintf(stderr, "Recieved invalid hash\n");
        goto error;
    }

    return sock;

error:
    return -2;
}

int handshake(const char *fname, const char *peer) {
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

    if (peer == NULL) {
        // pick a random one, useful for testing
        char temp[PEER_STRING_SIZE];
        int random_ret = random_peer(dict, info_hash, temp);
        if (random_ret != EX_OK) {
            ret = random_ret;
            goto end;
        }
        peer = temp;
    }
    fprintf(stderr, "Using peer %s\n", peer);
    // FIXME else should we validate supplied peer is on tracker?

    ret = EX_USAGE;
    char *colon = index(peer, ':');
    if (colon == NULL) goto end;
    *colon = 0;
    ret = EX_UNAVAILABLE;
    uint8_t response[HANDSHAKE_SIZE];
    int sock = handshake_peer(peer, colon + 1, info_hash, response);
    *colon = ':';
    if (sock == -1) goto end;
    if (sock < 0) {
        ret = EX_PROTOCOL;
        goto end;
    }
    uint8_t *peer_id = response + response[0] + 1 + RESERVED_SIZE + SHA1_DIGEST_BYTE_LENGTH;
    printf("Peer ID: ");
    for (int idx = 0; idx < PEER_ID_SIZE; idx ++) {
        printf("%02x", peer_id[idx]);
    }
    printf("\n");

    ret = EX_OK;
end:
    if (sock != -1) close(sock);
    if (decoded) {
        free((void*)decoded->start);
        free_bencoded_value(decoded);
    }
    if (errno) ret = errno;
    return ret;
}

bool parse_download_piece(int argc,  char **argv,  char *program,
         char **fname,  char **output, long *piece) {
    if (argc < 3) {
        if (argc < 2) {
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    program, "download_piece");
            return false;
        }
        *fname = argv[0];
        char *num_end = NULL;
        *piece = strtol(argv[1], &num_end, 10);
        if (*argv[1] != 0 && num_end && *num_end != 0) {
            fprintf(stderr, "Error: %s is not a number.\n", argv[1]);
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    program, "download_piece");
            return false;
        }
    } else {
        if (argc < 4) {
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    program, "download_piece");
            return false;
        }
        const char *piece_string = NULL;
        if (strcmp(argv[0], "-o") == 0) {
            *output = argv[1];
            *fname = argv[2];
            piece_string = argv[3];
        } else if (strcmp(argv[1], "-o") == 0) {
            *fname = argv[0];
            *output = argv[2];
            piece_string = argv[3];
        } else if (strcmp(argv[2], "-o") == 0) {
            *fname = argv[0];
            piece_string = argv[1];
            *output = argv[3];
        }
        char *num_end = NULL;
        *piece = strtol(piece_string, &num_end, 10);
        if (*piece_string != 0 && num_end && *num_end != 0) {
            fprintf(stderr, "Error: %s is not a number.\n", piece_string);
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    program, "download_piece");
            return false;
        }
    }
    return true;
}

bool read_full(int sock, void *data, size_t length) {
    ssize_t bytes_read = 0;
    while (bytes_read < length) {
        ssize_t read_ret = read(sock, data + bytes_read, length - bytes_read);
        if (read_ret <= 0) {
            fprintf(stderr, "ERROR Could only read %lu bytes out of %lu\n", bytes_read, length);
            return false;
        }
        bytes_read += read_ret;
        fprintf(stderr, "read %lu bytes out of %lu\n", bytes_read, length);
    }
    return true;
}

bool write_full(int sock, void *data, size_t length) {
    ssize_t bytes_written = 0;
    while (bytes_written < length) {
        ssize_t ret = write(sock, data + bytes_written, length - bytes_written);
        if (ret <= 0) {
            fprintf(stderr, "ERROR Could only send %lu bytes out of %lu\n", bytes_written, length);
            return false;
        }
        bytes_written += ret;
        fprintf(stderr, "written %lu bytes out of %lu\n", bytes_written, length);
    }
    return true;
}

int download_piece(int argc, char **argv, char *program) {
    // download_piece -o output sample.torrent <piece>
    char *fname = NULL;
    char *output = NULL;
    long piece;
    if (!parse_download_piece(argc, argv, program, &fname, &output, &piece)) {
        return EX_USAGE;
    }
    if (piece < 0) return EX_USAGE;

    FILE *out = output ? fopen(output, "w") : stdout;
    if (out == NULL) return EX_CANTCREAT;

    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(fname);
    if (!decoded || decoded->type != DICT) goto end;
    BencodedDict *dict = (BencodedDict *)decoded->data;

    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info || info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;
    BencodedValue *piece_length = bencoded_dict_value((BencodedDict *)info->data, "piece length");
    if (!piece_length || piece_length->type != INTEGER) goto end;
    BencodedValue *pieces = bencoded_dict_value((BencodedDict *)info->data, "pieces");
    if (!pieces || pieces->type != BYTES) goto end;

    if (piece > pieces->size / SHA1_DIGEST_BYTE_LENGTH) {
        fprintf(stderr, "Piece number out of range\n");
        ret = EX_USAGE;
        goto end;
    }

    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    // FIXME why not try all peers
    char peer[PEER_STRING_SIZE];
    int random_ret = random_peer(dict, info_hash, peer);
    if (random_ret != EX_OK) {
        ret = random_ret;
        goto end;
    }
    fprintf(stderr, "Using peer %s\n", peer);

    ret = EX_USAGE;
    char *colon = index(peer, ':');
    if (colon == NULL) goto end;
    *colon = 0;
    ret = EX_UNAVAILABLE;
    uint8_t response[HANDSHAKE_SIZE];
    int sock = handshake_peer(peer, colon + 1, info_hash, response);
    *colon = ':';
    if (sock == -1) goto end;
    ret = EX_PROTOCOL;
    if (sock < 0) goto end;

    // FIXME multiprocess

    uint32_t packet_length = 0;
    while (true) {
#define b(var) &var, sizeof(var)
        if (!read_full(sock, b(packet_length))) goto end;
        packet_length = ntohl(packet_length);
        fprintf(stderr, "packet length = %u\n", packet_length);
        if (packet_length > 0) {
            PeerMessageType type = CHOKE;
            if (!read_full(sock, b(type))) goto end;
            switch (type) {
                case UNCHOKE: {
                    // FIXME multiprocess
                    type = REQUEST;
                    RequestPayload payload = {
                        .index = htonl(piece),
                        .begin = 0,
                        .length = htonl(BLOCK_SIZE)
                    };
                    packet_length = htonl(sizeof(payload) + 1);
                    for (int idx = 0; idx < piece_length->size / BLOCK_SIZE; idx ++) {
                        payload.begin = htonl(idx * BLOCK_SIZE);
                        if (!write_full(sock, b(packet_length))) goto end;
                        if (!write_full(sock, b(type))) goto end;
                        if (!write_full(sock, b(payload))) goto end;
                    }
                    payload.length = piece_length->size % BLOCK_SIZE;
                    if (payload.length != 0) {
                        packet_length = htonl(payload.length);
                        payload.begin = htonl(BLOCK_SIZE * (piece_length->size / BLOCK_SIZE));
                        if (!write_full(sock, b(packet_length))) goto end;
                        if (!write_full(sock, b(type))) goto end;
                        if (!write_full(sock, b(payload))) goto end;
                    }

                    packet_length = 0;
                }; break;

                case BITFIELD: {
                    uint8_t payload;
                    if (!read_full(sock, b(payload))) goto end;
                    packet_length = htonl(1);
                    if (!write_full(sock, b(packet_length))) goto end;
                    type = INTERESTED;
                    if (!write_full(sock, b(type))) goto end;

                    packet_length = 0;
                }; break;


                default:
                    fprintf(stderr, "%s:%d: UNIMPLEMENTED type %d\n", __FILE__, __LINE__, type);
                    ret = EX_SOFTWARE;
                    goto end;
            }
        }
    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
end:
    if (sock != -1) close(sock);
    if (decoded) {
        free((void*)decoded->start);
        free_bencoded_value(decoded);
    }
    if (out && out != stdin) fclose(out);
    if (errno) ret = errno;
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
        fprintf(stderr, "    decode <bencoded_data>\n");
        fprintf(stderr, "    info <torrent_file>\n");
        fprintf(stderr, "    peers <torrent_file>\n");
        fprintf(stderr, "    handshake <torrent_file> [<peer:port>]\n");
        fprintf(stderr, "    download_piece [-o <output>] <torrent_file>\n");
        fprintf(stderr, "Available debug commands:\n");
        fprintf(stderr, "    parse\n");
        fprintf(stderr, "    hash\n");
        return EX_USAGE;
    }

    const char* command = argv[1];

    if (strcmp(command, "decode") == 0) {
        const char *encoded_str = argv[2];
        BencodedValue *value = decode_bencoded_bytes(encoded_str, encoded_str + strlen(encoded_str));
        if (!value) return EX_DATAERR;
        print_bencoded_value(value, (BencodedPrintConfig) {0});
        printf("\n");
        free_bencoded_value(value);
        return EX_OK;
    } else if (strcmp(command, "info") == 0) {
        const char *fname = argv[2];
        return info_file(fname);
    } else if (strcmp(command, "peers") == 0) {
        const char *fname = argv[2];
        return peers_file(fname);
    } else if (strcmp(command, "handshake") == 0) {
        const char *fname = argv[2];
        const char *peer = NULL;
        if (argc >= 3) peer = argv[3];
        return handshake(fname, peer);
    } else if (strcmp(command, "download_piece") == 0) {
        return download_piece(argc - 2, argv + 2, argv[0]);
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
        const char *fname = argv[2];
        return hash_file(fname);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return EX_USAGE;
    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
    return EX_SOFTWARE;
}
