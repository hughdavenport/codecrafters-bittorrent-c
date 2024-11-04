#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "bencode.h"
#include "sha1.h"
#include "peers.h"
#include "url.h"

int hash_file(const char *fname); // common.c
int download_piece_from_file(char *fname, char *output, long piece); // pieces.c

int handshake_file(const char *fname, const char *peer) {
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

    char *peer_str = NULL;
    if (peer == NULL) {
        // pick a random one, useful for testing
        char temp[PEER_STRING_SIZE];
        ret = EX_UNAVAILABLE;
        if (!random_peer(dict, info_hash, temp)) {
            goto end;
        }
        peer_str = strdup(temp);
    } else {
        peer_str = strdup(peer);
    }
    fprintf(stderr, "Using peer %s\n", peer_str);
    // FIXME else should we validate supplied peer is on tracker?

    ret = EX_USAGE;
    char *colon = index(peer_str, ':');
    if (colon == NULL) goto end;
    *colon = 0;
    ret = EX_UNAVAILABLE;
    uint8_t response[HANDSHAKE_SIZE];
    int sock = handshake_peer(peer_str, colon + 1, info_hash, response);
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
    if (peer_str) free(peer_str);
    if (sock != -1) close(sock);
    if (decoded) free_bencoded_value(decoded);
    return ret;
}

int info_file(const char *torrent_file) {
    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(torrent_file);
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
    for (size_t piece = 0; piece < pieces->size / SHA1_DIGEST_BYTE_LENGTH; piece ++) {
        for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
            printf("%02x", ((uint8_t *)pieces->data)[piece * SHA1_DIGEST_BYTE_LENGTH + idx]);
        }
        printf("\n");
    }
    printf("\n");

end:
    if (decoded) free_bencoded_value(decoded);
    return ret;
}

bool parse_download_piece(int argc,  char **argv,
         char **fname,  char **output, long *piece) {
    if (argc < 3) {
        if (argc < 2) {
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    "./your_bittorrent.sh", "download_piece");
            return false;
        }
        *fname = argv[0];
        char *num_end = NULL;
        *piece = strtol(argv[1], &num_end, 10);
        if (*argv[1] != 0 && num_end && *num_end != 0) {
            fprintf(stderr, "Error: %s is not a number.\n", argv[1]);
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    "./your_bittorrent.sh", "download_piece");
            return false;
        }
    } else {
        if (argc < 4) {
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent> <piece>\n",
                    "./your_bittorrent.sh", "download_piece");
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
                    "./your_bittorrent.sh", "download_piece");
            return false;
        }
    }
    return true;
}



int decode(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    const char *encoded_str = argv[0];
    BencodedValue *value = decode_bencoded_bytes((uint8_t *)encoded_str, (uint8_t *)encoded_str + strlen(encoded_str));
    if (!value) return EX_DATAERR;
    print_bencoded_value(value, (BencodedPrintConfig) {0});
    printf("\n");
    free_bencoded_value(value);
    return EX_OK;
}

int info(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    const char *torrent_file = argv[0];
    return info_file(torrent_file);
}

int peers(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    const char *torrent_file = argv[0];
    return peers_from_file(torrent_file);
}

int hash(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    const char *fname = argv[0];
    return hash_file(fname);
}

int handshake(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    const char *torrent_file = argv[0];
    const char *peer = NULL;
    if (argc >= 1) peer = argv[1];
    return handshake_file(torrent_file, peer);
}

int parse(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    int ret = EX_OK;
    URL url = {0};
    if (!parse_url(argv[0], NULL, &url)) ret = EX_DATAERR;
    printf("scheme = %s\n", url.scheme);
    printf("user = %s\n", url.user);
    printf("pass = %s\n", url.pass);
    printf("host = %s\n", url.host);
    printf("port = %s (%d)\n", url.port, url.port_num);
    printf("path = %s\n", url.path);
    printf("query = %s\n", url.query);
    printf("fragment = %s\n", url.fragment);
    return ret;
}

int download_piece(int argc, char **argv) {
    // download_piece -o output sample.torrent <piece>
    char *fname = NULL;
    char *output = NULL;
    long piece;
    if (!parse_download_piece(argc, argv, &fname, &output, &piece)) {
        return EX_USAGE;
    }
    if (piece < 0) return EX_USAGE;
    return download_piece_from_file(fname, output, piece);
}

