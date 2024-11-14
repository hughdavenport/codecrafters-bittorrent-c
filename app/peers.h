/*
MIT License

Copyright (c) 2024 Hugh Davenport

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef PEERS_H
#define PEERS_H

#define PEERS_H_VERSION_MAJOR "1"
#define PEERS_H_VERSION_MINOR "0"
#define PEERS_H_VERSION_PATCH "0"
#define PEERS_H_VERSION \
    PEERS_H_VERSION_MAJOR "." PEERS_H_VERSION_MINOR "." PEERS_H_VERSION_PATCH

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define DEPENDS_SHA1_H_VERSION_MAJOR 1
#define DEPENDS_SHA1_H_VERSION_MINOR 0
#define DEPENDS_SHA1_H_VERSION_PATCH 0
#define DEPENDS_SHA1_H_VERSION \
    TOSTRING(DEPENDS_SHA1_H_VERSION_MAJOR) "." \
    TOSTRING(DEPENDS_SHA1_H_VERSION_MINOR) "." \
    TOSTRING(DEPENDS_SHA1_H_VERSION_PATCH)

#if !defined(SHA1_H) || !defined(SHA1_H_VERSION_MAJOR) || !defined(SHA1_H_VERSION_MINOR) || !defined(SHA1_H_VERSION_PATCH)
#error "Depends on sha1.h. You can download this from https://github.com/hughdavenport/sha1.h"
#elif SHA1_H_VERSION_MAJOR < DEPENDS_SHA1_H_MAJOR || \
    (SHA1_H_VERSION_MAJOR == DEPENDS_SHA1_H_MAJOR && SHA1_H_VERSION_MINOR < DEPENDS_SHA1_H_MINOR) || \
    (SHA1_H_VERSION_MAJOR == DEPENDS_SHA1_H_MAJOR && SHA1_H_VERSION_MINOR == DEPENDS_SHA1_H_MINOR && SHA1_H_VERSION_PATCH < DEPENDS_SHA1_H_PATCH)
#error "Depends on sha1.h version " DEPENDS_SHA1_H_VERSION " or above. You can download this from https://github.com/hughdavenport/sha1.h"
#endif // !defined(SHA1_H)

#define DEPENDS_BENCODE_H_VERSION_MAJOR 1
#define DEPENDS_BENCODE_H_VERSION_MINOR 0
#define DEPENDS_BENCODE_H_VERSION_PATCH 0
#define DEPENDS_BENCODE_H_VERSION \
    TOSTRING(DEPENDS_BENCODE_H_VERSION_MAJOR) "." \
    TOSTRING(DEPENDS_BENCODE_H_VERSION_MINOR) "." \
    TOSTRING(DEPENDS_BENCODE_H_VERSION_PATCH)

#if !defined(BENCODE_H) || !defined(SHA1_H_VERSION_MAJOR) || !defined(SHA1_H_VERSION_MINOR) || !defined(SHA1_H_VERSION_PATCH)
#error "Depends on bencode.h. You can download this from https://github.com/hughdavenport/bencode.h"
#elif BENCODE_H_VERSION_MAJOR < DEPENDS_SHA1_H_MAJOR || \
    (BENCODE_H_VERSION_MAJOR == DEPENDS_SHA1_H_MAJOR && SHA1_H_VERSION_MINOR < DEPENDS_SHA1_H_MINOR) || \
    (BENCODE_H_VERSION_MAJOR == DEPENDS_SHA1_H_MAJOR && SHA1_H_VERSION_MINOR == DEPENDS_SHA1_H_MINOR && SHA1_H_VERSION_PATCH < DEPENDS_SHA1_H_PATCH)
#error "Depends on bencode.h version " DEPENDS_BENCODE_H_VERSION " or above. You can download this from https://github.com/hughdavenport/bencode.h"
#endif // !defined(BENCODE_H)

#include <stdint.h>
#include <stdbool.h>

#define HANDSHAKE_SIZE 68
#define EXTENSIONS_SIZE 8
#define PEER_ID_SIZE 20

// Enough space for xxx.xxx.xxx.xxx:xxxxx\0
#define PEER_STRING_SIZE 23

// prints peers out after making a request to the tracker
int peers_from_file(const char *torrent_file);

// Pick a random peer after making a request to the tracker
bool random_peer(BencodedDict *dict, uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH], char peer[PEER_STRING_SIZE]);

// Returns a socket connected to a peer immediately after a handshake has occurred
int handshake_peer(const char *host, const char *port, const uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH], uint8_t response[HANDSHAKE_SIZE]);

#endif // PEERS_H

#ifdef PEERS_IMPLEMENTATION

#include <time.h>
#include <assert.h>

// 20 byte identifier. This is random data
#define PEER_ID "AdtLtU86udGzzN5m9GDs"
#define HANDSHAKE_PROTOCOL "BitTorrent protocol"

#define TRACKER_IMPLEMENTATION
#include "tracker.h"

int peers_from_file(const char *torrent_file) {
    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(torrent_file, true);
    if (!decoded) goto end;
    if (decoded->type != DICT) goto end;
    BencodedDict *dict = (BencodedDict *)decoded->data;
    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;

    // info->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    BencodedValue *response = NULL;
    int tracker_ret = tracker_response(dict, info_hash, &response);
    if (tracker_ret != EX_OK) {
        ret = tracker_ret;
        goto end;
    }
    ret = EX_PROTOCOL;
    if (!response || response->type != DICT) goto end;
    BencodedValue *peers = bencoded_dict_value((BencodedDict *)response->data, "peers");
    if (!peers || peers->type != BYTES) goto end;
    if (peers->size % 6 != 0) goto end;

    for (size_t idx = 0; (idx + 1) * 6 <= peers->size; idx ++) {
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
    if (decoded) {
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
    if (response) free_bencoded_value(response);
    return ret;
}

bool random_peer(BencodedDict *dict,
        uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        char peer[PEER_STRING_SIZE]) {
    bool ret = false;
    BencodedValue *response = NULL;
    int tracker_ret = tracker_response(dict, info_hash, &response);
    if (tracker_ret != EX_OK) {
        ret = tracker_ret;
        goto end;
    }
    if (!response || response->type != DICT) goto end;
    BencodedValue *peers = bencoded_dict_value((BencodedDict *)response->data, "peers");
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
        goto end;
    }

    ret = true;
end:
    if (response) free_bencoded_value(response);
    return ret;
}

int connect_peer(const char *host, const char *port) {
    struct addrinfo hints = {0};
    struct addrinfo *result, *rp = NULL;
    int ret = -1;

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

    // FIXME in common.c, no good for header only
bool write_full(int sock, void *data, size_t length);

#define NUM_BITTORRENT_EXTENSIONS 8
#define SET_BITTORRENT_EXTENSION(extensions, extension) do { \
    static_assert((extension) < NUM_BITTORRENT_EXTENSIONS * 8); \
    (extensions)[(extension) / NUM_BITTORRENT_EXTENSIONS] |= \
        (1 << ((extension) % NUM_BITTORRENT_EXTENSIONS)); \
} while (0);

#define BITTORRENT_EXTENSION_PROTOCOL 44

int handshake_peer(const char *host,
        const char *port,
        const uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        uint8_t response[HANDSHAKE_SIZE]) {
    int sock = connect_peer(host, port);
    if (sock == -1) return -1;

    int len = 0;
    len += dprintf(sock, "%c", (char)strlen(HANDSHAKE_PROTOCOL));
    len += dprintf(sock, HANDSHAKE_PROTOCOL);
    // Extensions
    uint8_t extensions[NUM_BITTORRENT_EXTENSIONS] = {0};
    SET_BITTORRENT_EXTENSION(extensions, BITTORRENT_EXTENSION_PROTOCOL);
    // FIXME in common.c, no good for header only
    if (write_full(sock, extensions, NUM_BITTORRENT_EXTENSIONS)) {
        len += NUM_BITTORRENT_EXTENSIONS;
    }
    for (int idx = 0; idx < EXTENSIONS_SIZE; idx ++) {
        if (extensions[idx] != 0) {
            fprintf(stderr, "WARN: sent extension[%d] = 0x%02x\n", idx, extensions[idx]);
        }
    }

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
    if (strncmp((char *)response + 1, HANDSHAKE_PROTOCOL, response[0]) != 0) goto error;
    uint8_t *reserved = response + response[0] + 1;
    for (int idx = 0; idx < EXTENSIONS_SIZE; idx ++) {
        if (reserved[idx] != 0) {
            fprintf(stderr, "WARN: received reserved[%d] = 0x%02x\n", idx, reserved[idx]);
        }
    }
    // FIXME: work out what reserved bits mean what extension
    if (memcmp(reserved + EXTENSIONS_SIZE, info_hash, SHA1_DIGEST_BYTE_LENGTH) != 0) {
        fprintf(stderr, "Recieved invalid hash\n");
        goto error;
    }

    return sock;

error:
    return -2;
}

#endif // PEERS_IMPLEMENTATION
