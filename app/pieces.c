#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sysexits.h>

#include "bencode.h"
#include "sha1.h"
#include "peers.h"

#include "io.h"

// 2^14 (16 kiB)
#define BLOCK_SIZE 16384

typedef struct {
    uint32_t index;
    uint32_t begin;
    uint32_t length;
} RequestPayload;

int download_from_file(char *fname, char *output) {
    uint8_t *full_data = NULL;
    int sock = -1;
    BencodedValue *decoded = NULL;
    FILE *out = output ? fopen(output, "w") : stdout;
    if (out == NULL) return EX_CANTCREAT;
    int out_fd = fileno(out);
    int ret = EX_IOERR;
    if (out_fd < 0) goto end;

    ret = EX_DATAERR;
    decoded = decode_bencoded_file(fname, true);
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

    size_t num_pieces = pieces->size / SHA1_DIGEST_BYTE_LENGTH;
    if ((num_pieces - 1) * piece_length->size > length->size) {
        fprintf(stderr, "Overflow of length with piece size\n");
        goto end;
    }

    ret = EX_DATAERR;
    // info->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    full_data = malloc(length->size);
    if (full_data == NULL) goto end;

    // FIXME why not try all peers
    char peer[PEER_STRING_SIZE];
    ret = EX_UNAVAILABLE;
    if (!random_peer_from_dict(dict, info_hash, peer)) {
        goto end;
    }
    fprintf(stderr, "Using peer %s\n", peer);

    ret = EX_USAGE;
    char *colon = index(peer, ':');
    if (colon == NULL) goto end;
    *colon = 0;
    ret = EX_UNAVAILABLE;
    uint8_t response[HANDSHAKE_SIZE];
    sock = handshake_peer(peer, colon + 1, info_hash, response);
    *colon = ':';
    if (sock == -1) goto end;
    ret = EX_PROTOCOL;
    if (sock < 0) goto end;

    // FIXME multiprocess

    uint32_t packet_length = 0;
    size_t sent_requests = 0;
    size_t pieces_recieved = 0;
    while (sent_requests == 0 || pieces_recieved < sent_requests) {
        if (!read_full(sock, packet_length)) goto end;
        packet_length = ntohl(packet_length);
        fprintf(stderr, "packet length = %u\n", packet_length);
        if (packet_length > 0) {
            PeerMessageType type = CHOKE;
            if (!read_full_length(sock, &type, 1)) goto end;
            packet_length -= 1;
            switch (type) {
                case UNCHOKE: {
                    fprintf(stderr, "got UNCHOKE\n");
                    // FIXME multiprocess
                    if (packet_length > 0) fprintf(stderr, "unexpected payload\n");
                    while (packet_length > 0) {
                        uint8_t payload;
                        if (!read_full(sock, payload)) goto end;
                        packet_length -= 1;
                    }

                    for (size_t piece = 0; piece < num_pieces; ++piece) {
                        size_t len = piece_length->size;
                        if ((unsigned)piece + 1 == num_pieces) {
                            len = length->size - (num_pieces - 1) * piece_length->size;
                        }
                        type = REQUEST;
                        RequestPayload payload = {
                            .index = htonl(piece),
                            .begin = 0,
                            .length = htonl(BLOCK_SIZE)
                        };

                        packet_length = htonl(sizeof(payload) + 1);
                        for (size_t idx = 0; idx < len / BLOCK_SIZE; idx ++) {
                            if (!write_full(sock, packet_length)) goto end;
                            if (!write_full_length(sock, &type, 1)) goto end;
                            if (!write_full(sock, payload)) goto end;
                            sent_requests ++;
                            fprintf(stderr, "Sent REQUEST for piece %d, begin %d, length %d\n",
                                    ntohl(payload.index), ntohl(payload.begin), ntohl(payload.length));
                            payload.begin = htonl(ntohl(payload.begin) + ntohl(payload.length));
                        }
                        payload.length = len % BLOCK_SIZE;
                        if (payload.length != 0) {
                            payload.length = htonl(payload.length);
                            if (!write_full(sock, packet_length)) goto end;
                            if (!write_full_length(sock, &type, 1)) goto end;
                            if (!write_full(sock, payload)) goto end;
                            sent_requests ++;
                            fprintf(stderr, "Sent smaller REQUEST for piece %d, begin %d, length %d\n",
                                    ntohl(payload.index), ntohl(payload.begin), ntohl(payload.length));
                        }
                    }

                    packet_length = 0;
                }; break;

                case BITFIELD: {
                    fprintf(stderr, "got BITFIELD\n");
                    while (packet_length > 0) {
                        uint8_t payload;
                        if (!read_full(sock, payload)) goto end;
                        /* fprintf(stderr, "bitfield payload %08b\n", payload); */
                        // FIXME check if 1 << (8 - piece) is set in the right byte
                        packet_length -= 1;
                    }
                    packet_length = htonl(1);
                    if (!write_full(sock, packet_length)) goto end;
                    type = INTERESTED;
                    if (!write_full_length(sock, &type, 1)) goto end;
                    fprintf(stderr, "Sent INTERESTED\n");

                    packet_length = 0;
                }; break;

                case PIECE: {
                    fprintf(stderr, "got PIECE\n");
                    if (packet_length < sizeof(uint32_t) * 2) {
                        fprintf(stderr, "Expected index and begin, but only %u bytes in packet\n",
                                packet_length);
                        goto end;
                    }
                    if (sent_requests == 0 || pieces_recieved >= sent_requests) {
                        fprintf(stderr, "Unexpected PIECE message\n");
                        goto end;
                    }

                    uint32_t piece, begin;
                    if (!read_full(sock, piece)) goto end;
                    piece = ntohl(piece);
                    if (!read_full(sock, begin)) goto end;
                    begin = ntohl(begin);
                    packet_length -= sizeof(uint32_t) * 2;

                    if (piece >= num_pieces) goto end;
                    uint8_t *data = full_data + (piece * piece_length->size);
                    fprintf(stderr, "full_data + length->size = %p\n", (void*)(full_data + length->size));
                    fprintf(stderr, "data + begin + packet_length = %p\n", (void*)(data + begin + packet_length));
                    if (full_data + length->size < data + begin + packet_length) {
                        goto end;
                    }

                    // FIXME validate begin are in range
                    if (!read_full_length(sock, data + begin, packet_length)) goto end;
                    fprintf(stderr, "Got request for piece %d, begin %d, length %d\n",
                            piece, begin, packet_length);

                    pieces_recieved ++;
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

    for (size_t piece = 0; piece < num_pieces; ++piece) {
        uint8_t *data = full_data + (piece * piece_length->size);
        size_t len = piece_length->size;
        if ((unsigned)piece + 1 == num_pieces) {
            len = length->size - (num_pieces - 1) * piece_length->size;
        }
        // FIXME check hash
        uint8_t piece_hash[SHA1_DIGEST_BYTE_LENGTH];
        if (!sha1_digest(data, len, piece_hash)) {
            goto end;
        }

        if (memcmp(piece_hash,
                    (uint8_t *)pieces->data + piece * SHA1_DIGEST_BYTE_LENGTH,
                    SHA1_DIGEST_BYTE_LENGTH) != 0) {
            fprintf(stderr, "Piece hash mixmatch for piece %ld\n", piece);
            fprintf(stderr, "Expected: ");
            for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
                fprintf(stderr, "%02x", ((uint8_t *)pieces->data)[piece * SHA1_DIGEST_BYTE_LENGTH + idx]);
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "Actual:   ");
            SHA1_FPRINTF_HEX(stderr, piece_hash);
            fprintf(stderr, "\n");
            goto end;
        }
    }

    ret = EX_IOERR;
    if (!write_full_length(out_fd, full_data, length->size)) {
        fprintf(stderr, "Could not write output file\n");
        goto end;
    }

    ret = EX_OK;

end:
    if (full_data) free(full_data);
    if (sock != -1) close(sock);
    if (decoded) {
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
    if (out && out != stdin) fclose(out);
    return ret;
}

int download_piece_from_file(char *fname, char *output, long piece) {
    FILE *out = output ? fopen(output, "w") : stdout;
    int sock = -1;
    BencodedValue *decoded = NULL;
    uint8_t *data = NULL;
    if (out == NULL) return EX_CANTCREAT;
    int out_fd = fileno(out);
    int ret = EX_IOERR;
    if (out_fd < 0) goto end;

    ret = EX_DATAERR;
    decoded = decode_bencoded_file(fname, true);
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

    size_t num_pieces = pieces->size / SHA1_DIGEST_BYTE_LENGTH;
    if ((unsigned)piece >= num_pieces) {
        fprintf(stderr, "Piece number out of range\n");
        ret = EX_USAGE;
        goto end;
    }
    if ((num_pieces - 1) * piece_length->size > length->size) {
        fprintf(stderr, "Overflow of length with piece size\n");
        goto end;
    }
    size_t len = piece_length->size;
    if ((unsigned)piece + 1 == num_pieces) {
        len = length->size - (num_pieces - 1) * piece_length->size;
    }

    ret = EX_DATAERR;
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
    if (!random_peer_from_dict(dict, info_hash, peer)) {
        goto end;
    }
    fprintf(stderr, "Using peer %s\n", peer);

    ret = EX_USAGE;
    char *colon = index(peer, ':');
    if (colon == NULL) goto end;
    *colon = 0;
    ret = EX_UNAVAILABLE;
    uint8_t response[HANDSHAKE_SIZE];
    sock = handshake_peer(peer, colon + 1, info_hash, response);
    *colon = ':';
    if (sock == -1) goto end;
    ret = EX_PROTOCOL;
    if (sock < 0) goto end;

    data = malloc(len);
    if (data == NULL) {
        ret = EX_TEMPFAIL;
        goto end;
    }

    // FIXME multiprocess

    uint32_t packet_length = 0;
    size_t sent_requests = 0;
    size_t pieces_recieved = 0;
    while (sent_requests == 0 || pieces_recieved < sent_requests) {
        if (!read_full(sock, packet_length)) goto end;
        packet_length = ntohl(packet_length);
        fprintf(stderr, "packet length = %u\n", packet_length);
        if (packet_length > 0) {
            PeerMessageType type = CHOKE;
            if (!read_full_length(sock, &type, 1)) goto end;
            packet_length -= 1;
            switch (type) {
                case UNCHOKE: {
                    fprintf(stderr, "got UNCHOKE\n");
                    // FIXME multiprocess
                    if (packet_length > 0) fprintf(stderr, "unexpected payload\n");
                    while (packet_length > 0) {
                        uint8_t payload;
                        if (!read_full(sock, payload)) goto end;
                        packet_length -= 1;
                    }

                    type = REQUEST;
                    RequestPayload payload = {
                        .index = htonl(piece),
                        .begin = 0,
                        .length = htonl(BLOCK_SIZE)
                    };

                    packet_length = htonl(sizeof(payload) + 1);
                    for (size_t idx = 0; idx < len / BLOCK_SIZE; idx ++) {
                        if (!write_full(sock, packet_length)) goto end;
                        if (!write_full_length(sock, &type, 1)) goto end;
                        if (!write_full(sock, payload)) goto end;
                        sent_requests ++;
                        fprintf(stderr, "Sent REQUEST for piece %d, begin %d, length %d\n",
                                ntohl(payload.index), ntohl(payload.begin), ntohl(payload.length));
                        payload.begin = htonl(ntohl(payload.begin) + ntohl(payload.length));
                    }
                    payload.length = len % BLOCK_SIZE;
                    if (payload.length != 0) {
                        payload.length = htonl(payload.length);
                        if (!write_full(sock, packet_length)) goto end;
                        if (!write_full_length(sock, &type, 1)) goto end;
                        if (!write_full(sock, payload)) goto end;
                        sent_requests ++;
                        fprintf(stderr, "Sent smaller REQUEST for piece %d, begin %d, length %d\n",
                                ntohl(payload.index), ntohl(payload.begin), ntohl(payload.length));
                    }

                    packet_length = 0;
                }; break;

                case BITFIELD: {
                    fprintf(stderr, "got BITFIELD\n");
                    while (packet_length > 0) {
                        uint8_t payload;
                        if (!read_full(sock, payload)) goto end;
                        /* fprintf(stderr, "bitfield payload %08b\n", payload); */
                        // FIXME check if 1 << (8 - piece) is set in the right byte
                        packet_length -= 1;
                    }
                    packet_length = htonl(1);
                    if (!write_full(sock, packet_length)) goto end;
                    type = INTERESTED;
                    if (!write_full_length(sock, &type, 1)) goto end;
                    fprintf(stderr, "Sent INTERESTED\n");

                    packet_length = 0;
                }; break;

                case PIECE: {
                    fprintf(stderr, "got PIECE\n");
                    if (packet_length < sizeof(uint32_t) * 2) {
                        fprintf(stderr, "Expected index and begin, but only %u bytes in packet\n",
                                packet_length);
                        goto end;
                    }
                    if (sent_requests == 0 || pieces_recieved >= sent_requests) {
                        fprintf(stderr, "Unexpected PIECE message\n");
                        goto end;
                    }

                    uint32_t index, begin;
                    if (!read_full(sock, index)) goto end;
                    index = ntohl(index);
                    if (!read_full(sock, begin)) goto end;
                    begin = ntohl(begin);
                    packet_length -= sizeof(uint32_t) * 2;

                    if (index != piece) {
                        fprintf(stderr, "Expected index %ld, got %d\n",
                                piece, index);
                        goto end;
                    }

                    // FIXME validate begin are in range
                    if (!read_full_length(sock, data + begin, packet_length)) goto end;
                    fprintf(stderr, "Got request for piece %d, begin %d, length %d\n",
                            index, begin, packet_length);

                    pieces_recieved ++;
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

    // FIXME check hash
    uint8_t piece_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest(data, len, piece_hash)) {
        goto end;
    }

    if (memcmp(piece_hash,
                (uint8_t *)pieces->data + piece * SHA1_DIGEST_BYTE_LENGTH,
                SHA1_DIGEST_BYTE_LENGTH) != 0) {
        fprintf(stderr, "Piece hash mixmatch\n");
        fprintf(stderr, "Expected: ");
        for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
            fprintf(stderr, "%02x", ((uint8_t *)pieces->data)[piece * SHA1_DIGEST_BYTE_LENGTH + idx]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "Actual:   ");
        SHA1_FPRINTF_HEX(stderr, piece_hash);
        fprintf(stderr, "\n");
        goto end;
    }


    ret = EX_IOERR;
    if (!write_full_length(out_fd, data, len)) {
        fprintf(stderr, "Could not write output file\n");
        goto end;
    }

    ret = EX_OK;

end:
    if (data) free(data);
    if (sock != -1) close(sock);
    if (decoded) {
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
    if (out && out != stdin) fclose(out);
    return ret;
}
