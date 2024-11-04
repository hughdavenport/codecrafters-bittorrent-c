#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sysexits.h>

#include "bencode.h"
#include "sha1.h"
#include "peers.h"

// in common.c
bool read_full(int sock, void *data, size_t length);
bool write_full(int sock, void *data, size_t length);

// 2^14 (16 kiB)
#define BLOCK_SIZE 16384

typedef enum {
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

int download_piece_from_file(char *fname, char *output, long piece) {
    FILE *out = output ? fopen(output, "w") : stdout;
    if (out == NULL) return EX_CANTCREAT;

    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(fname, true);
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

    if ((unsigned)piece > pieces->size / SHA1_DIGEST_BYTE_LENGTH) {
        fprintf(stderr, "Piece number out of range\n");
        ret = EX_USAGE;
        goto end;
    }

    // info->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    // FIXME why not try all peers
    char peer[PEER_STRING_SIZE];
    ret = EX_UNAVAILABLE;
    if (!random_peer(dict, info_hash, peer)) {
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

    if (sizeof(RequestPayload) != 16) {
        fprintf(stderr, "sizeof(RequestPayload) != 16 (got %ld)\n", sizeof(RequestPayload));
    }

    uint32_t packet_length = 0;
    while (true) {
#define b(var) &var, sizeof(var)
        if (!read_full(sock, b(packet_length))) goto end;
        packet_length = ntohl(packet_length);
        fprintf(stderr, "packet length = %u\n", packet_length);
        if (packet_length > 0) {
            PeerMessageType type = CHOKE;
            if (!read_full(sock, &type, 1)) goto end;
            packet_length -= 1;
            switch (type) {
                case UNCHOKE: {
                    fprintf(stderr, "got UNCHOKE\n");
                    // FIXME multiprocess
                    while (packet_length > 0) {
                        uint8_t payload;
                        if (!read_full(sock, b(payload))) goto end;
                        packet_length -= 1;
                    }
                    type = REQUEST;
                    RequestPayload payload = {
                        .index = htonl(piece),
                        .begin = 0,
                        .length = htonl(BLOCK_SIZE)
                    };

                    packet_length = htonl(sizeof(payload) + 1);
                    for (size_t idx = 0; idx < piece_length->size / BLOCK_SIZE; idx ++) {
                        payload.begin = htonl(idx * BLOCK_SIZE);
                        if (!write_full(sock, b(packet_length))) goto end;
                        if (!write_full(sock, &type, 1)) goto end;
                        if (!write_full(sock, b(payload))) goto end;
                    }
                    payload.length = piece_length->size % BLOCK_SIZE;
                    if (payload.length != 0) {
                        packet_length = htonl(payload.length);
                        payload.begin = htonl(BLOCK_SIZE * (piece_length->size / BLOCK_SIZE));
                        if (!write_full(sock, b(packet_length))) goto end;
                        if (!write_full(sock, &type, 1)) goto end;
                        if (!write_full(sock, b(payload))) goto end;
                    }

                    packet_length = 0;
                }; break;

                case BITFIELD: {
                    fprintf(stderr, "got BITFIELD\n");
                    while (packet_length > 0) {
                        uint8_t payload;
                        if (!read_full(sock, b(payload))) goto end;
                        packet_length -= 1;
                    }
                    packet_length = htonl(1);
                    if (!write_full(sock, b(packet_length))) goto end;
                    type = INTERESTED;
                    if (!write_full(sock, &type, 1)) goto end;

                    packet_length = 0;
                }; break;


                default:
                    if (type > CANCEL) {
                        fprintf(stderr, "%s:%d: UNREACHABLE: Bad type %d\n", __FILE__, __LINE__, type);
                        ret = EX_SOFTWARE;
                        goto end;
                    }
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
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
    if (out && out != stdin) fclose(out);
    return ret;
}
