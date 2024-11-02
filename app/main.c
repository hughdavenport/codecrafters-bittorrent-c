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

#define HTTP_IMPLEMENTATION
#include "http.h"

#define PEERS_IMPLEMENTATION
#include "peers.h"

int decode(int argc, char **argv);
int info(int argc, char **argv);
int peers(int argc, char **argv);
int hash(int argc, char **argv);
int handshake(int argc, char **argv);
int parse(int argc, char **argv);

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
    while ((size_t)bytes_read < length) {
        ssize_t read_ret = read(sock, (uint8_t *)data + bytes_read, length - bytes_read);
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
    while ((size_t)bytes_written < length) {
        ssize_t ret = write(sock, (uint8_t *)data + bytes_written, length - bytes_written);
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

    if ((unsigned)piece > pieces->size / SHA1_DIGEST_BYTE_LENGTH) {
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
        return decode(argc - 2, argv + 2);
    } else if (strcmp(command, "info") == 0) {
        return info(argc - 2, argv + 2);
    } else if (strcmp(command, "peers") == 0) {
        return peers(argc - 2, argv + 2);
    } else if (strcmp(command, "handshake") == 0) {
        return handshake(argc - 2, argv + 2);
    } else if (strcmp(command, "download_piece") == 0) {
        return download_piece(argc - 2, argv + 2, argv[0]);
    } else if (strcmp(command, "parse") == 0) {
        return parse(argc - 2, argv + 2);
    } else if (strcmp(command, "hash") == 0) {
        return hash(argc - 2, argv + 2);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return EX_USAGE;
    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
    return EX_SOFTWARE;
}
