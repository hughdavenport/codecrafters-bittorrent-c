#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sysexits.h>
#include <errno.h>

#include <unistd.h>

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

// FIXME set up a proper define, or part of url.h
#include "url-query.h"

#ifdef BITTORRENT_RELEASE
#define ERR_OUT(fmt, ...) \
        fprintf(stderr, (fmt), __VA_ARGS__)
#else
#define ERR_OUT(fmt, ...) \
        fprintf(stderr, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#define TODO(msg) ERR_OUT("%s\n", (msg))
#endif

int hash_file(const char *fname); // common.c
int download_piece_from_file(char *fname, char *output, long piece); // pieces.c
int download_from_file(char *fname, char *output); // pieces.c

int handshake_file(const char *fname, const char *peer) {
    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(fname, true);
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

    char *peer_str = NULL;
    if (peer == NULL) {
        // pick a random one, useful for testing
        char temp[PEER_STRING_SIZE];
        ret = EX_UNAVAILABLE;
        if (!random_peer_from_dict(dict, info_hash, temp)) {
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
    uint8_t *peer_id = response + response[0] + 1 + EXTENSIONS_SIZE + SHA1_DIGEST_BYTE_LENGTH;
    printf("Peer ID: ");
    for (int idx = 0; idx < PEER_ID_SIZE; idx ++) {
        printf("%02x", peer_id[idx]);
    }
    printf("\n");

    ret = EX_OK;
end:
    if (peer_str) free(peer_str);
    if (sock != -1) close(sock);
    if (decoded) {
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
    return ret;
}

int info_file(const char *torrent_file) {
    int ret = EX_DATAERR;
    BencodedValue *decoded = decode_bencoded_file(torrent_file, true);
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

    // info->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
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
    if (decoded) {
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
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

bool parse_download(int argc,  char **argv, char **fname,  char **output) {
    if (argc < 2) {
        if (argc < 1) {
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent>\n",
                    "./your_bittorrent.sh", "download");
            return false;
        }
        *fname = argv[0];
    } else {
        if (argc < 3) {
            fprintf(stderr, "Usage %s %s [-o <output>] <torrent>\n",
                    "./your_bittorrent.sh", "download");
            return false;
        }
        if (strcmp(argv[0], "-o") == 0) {
            *output = argv[1];
            *fname = argv[2];
        } else if (strcmp(argv[1], "-o") == 0) {
            *fname = argv[0];
            *output = argv[2];
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

int download(int argc, char **argv) {
    // download -o output sample.torrent
    char *fname = NULL;
    char *output = NULL;
    if (!parse_download(argc, argv, &fname, &output)) {
        return EX_USAGE;
    }
    return download_from_file(fname, output);
}


int magnet_parse(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    URL url = {0};
    if (!parse_url(argv[0], NULL, &url)) return EX_DATAERR;
    if (strcmp(url.scheme, "magnet") != 0) {
        fprintf(stderr, "Expected magnet url\n");
        return EX_DATAERR;
    }
    URLQueryParameters parameters = {0};
    int ret = EX_DATAERR;
    if (!url_parse_query(&url, &parameters)) goto end;
    URLQueryParameter *xt = url_query_parameter(&parameters, &cstr_to_byte_buffer("xt"));
    URLQueryParameter *tr = url_query_parameter(&parameters, &cstr_to_byte_buffer("tr"));
    if (!xt) {
        fprintf(stderr, "Couldn't find `xt` query parameter.\n");
        goto end;
    }
    if (xt->size != 1) {
        fprintf(stderr, "Expected exactly 1 `xt` query parameter.\n");
        goto end;
    }

    if (xt->value.size < 9) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%*s`\n",
                (int)xt->value.size, xt->value.data);
        goto end;
    }
    if (memcmp(xt->value.data, "urn:", 4) != 0) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%4s...`\n",
                xt->value.data);
        goto end;
    }
    char *hash_type = (char *)xt->value.data + 4;
    if (memcmp(hash_type, "btih:", 5) != 0 && memcmp(hash_type, "btmh:", 5) != 0) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%9s...`\n",
                xt->value.data);
        goto end;
    }
    if (memcmp(hash_type, "btmh", 4) == 0) {
        fprintf(stderr, "Don't support magnet v2 links, yet.\n");
        goto end;
    }

    char *hash = (char *)xt->value.data + 9;
    if (xt->value.size - 9 != 40) {
        if (xt->value.size - 9 != 32) {
            fprintf(stderr, "Expected a 40 char hex encoded or 32 character base32 encoded info hash in `xt`, but got length %ld\n",
                    xt->value.size - 9);

            goto end;
        }
        TODO("base32 encoded");
        goto end;
    } else {
        // FIXME validate the hash is hex?
    }

    if (tr && (tr->size == 1 || (tr->size > 1 && tr->data))) {
        if (tr->size > 1) {
            TODO("multiple trackers");
        } else {
            printf("Tracker URL: %s\n", tr->value.data);
        }
    }
    printf("Info Hash: %s\n", hash);

    ret = EX_OK;
end:
    free_url_query_parameters(&parameters);
    return ret;
}


int magnet_handshake(int argc, char **argv) {
    if (argc == 0) return EX_USAGE;
    URL url = {0};
    if (!parse_url(argv[0], NULL, &url)) return EX_DATAERR;
    if (strcmp(url.scheme, "magnet") != 0) {
        fprintf(stderr, "Expected magnet url\n");
        return EX_DATAERR;
    }
    URLQueryParameters parameters = {0};
    int ret = EX_DATAERR;
    if (!url_parse_query(&url, &parameters)) goto end;
    URLQueryParameter *xt = url_query_parameter(&parameters, &cstr_to_byte_buffer("xt"));
    URLQueryParameter *tr = url_query_parameter(&parameters, &cstr_to_byte_buffer("tr"));
    if (!xt) {
        fprintf(stderr, "Couldn't find `xt` query parameter.\n");
        goto end;
    }
    if (xt->size != 1) {
        fprintf(stderr, "Expected exactly 1 `xt` query parameter.\n");
        goto end;
    }

    if (xt->value.size < 9) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%*s`\n",
                (int)xt->value.size, xt->value.data);
        goto end;
    }
    if (memcmp(xt->value.data, "urn:", 4) != 0) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%4s...`\n",
                xt->value.data);
        goto end;
    }
    char *hash_type = (char *)xt->value.data + 4;
    if (memcmp(hash_type, "btih:", 5) != 0 && memcmp(hash_type, "btmh:", 5) != 0) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%9s...`\n",
                xt->value.data);
        goto end;
    }
    if (memcmp(hash_type, "btmh", 4) == 0) {
        fprintf(stderr, "Don't support magnet v2 links, yet.\n");
        goto end;
    }

    char *hash = (char *)xt->value.data + 9;
    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (xt->value.size - 9 != 2 * SHA1_DIGEST_BYTE_LENGTH) {
        if (xt->value.size - 9 != 32) {
            fprintf(stderr, "Expected a 40 char hex encoded or 32 character base32 encoded info hash in `xt`, but got length %ld\n",
                    xt->value.size - 9);

            goto end;
        }
        TODO("base32 encoded");
        goto end;
    } else {
        for (size_t idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
            uint8_t c1 = hash[2*idx];
            uint8_t c2 = hash[2*idx + 1];
            if (!isxdigit(c1) || !isxdigit(c2)) {
                fprintf(stderr, "Expected 40 char hex encoded info hash. Found non hex character at idx %zu\n",
                        idx);
                goto end;
            }
            uint8_t d1 = 0, d2 = 0;
            if (isdigit(c1)) {
                d1 = c1 - '0';
            } else {
                d1 = 10 + tolower(c1) - 'a';
            }
            if (isdigit(c2)) {
                d2 = c2 - '0';
            } else {
                d2 = 10 + tolower(c2) - 'a';
            }
            if (d1 > 0xF || d2 > 0xF) {
                fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
                return EX_SOFTWARE;
            }
            info_hash[idx] = d1 << 4 | d2;
        }
    }

    printf("Info Hash: ");
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        printf("%02x", info_hash[idx]);
    }
    printf("\n");

    URL tracker;
    if (tr && (tr->size == 1 || (tr->size > 1 && tr->data))) {
        if (tr->size > 1) {
            TODO("multiple trackers");
        } else {
            char *track = (char *)tr->value.data;
            if (!parse_url(track, NULL, &tracker)) {
                goto end;
            }
        }
    }

    BencodedValue *response = NULL;
    size_t length = 0; // FIXME what should this be?
    int tracker_ret = tracker_response_from_url(&tracker, 0, 0, length, info_hash, &response);
    if (tracker_ret != EX_OK) {
        ret = tracker_ret;
        goto end;
    }

    char peer[PEER_STRING_SIZE];
    ret = EX_UNAVAILABLE;
    if (!random_peer_from_response(response, peer)) {
        goto end;
    }
    fprintf(stderr, "Using peer %s\n", peer);

    ret = EX_OK;
end:
    free_url_query_parameters(&parameters);
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
        return download_piece(argc - 2, argv + 2);
    } else if (strcmp(command, "download") == 0) {
        return download(argc - 2, argv + 2);
    } else if (strcmp(command, "magnet_parse") == 0) {
        return magnet_parse(argc - 2, argv + 2);
    } else if (strcmp(command, "magnet_handshake") == 0) {
        return magnet_handshake(argc - 2, argv + 2);
    } else if (strcmp(command, "parse") == 0) {
        return parse(argc - 2, argv + 2);
    } else if (strcmp(command, "hash") == 0) {
        return hash(argc - 2, argv + 2);
    } else {
        ERR_OUT("Unknown command: %s\n", command);
        return EX_USAGE;
    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
    return EX_SOFTWARE;
}
