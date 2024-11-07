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

#ifdef BITTORRENT_RELEASE
#define ERR_OUT(fmt, ...) \
        fprintf(stderr, (fmt), __VA_ARGS__)
#else 
#define ERR_OUT(fmt, ...) \
        fprintf(stderr, "%s:%d: " fmt, __FILE__, __LINE__, __VA_ARGS__)
#endif

int decode(int argc, char **argv);
int info(int argc, char **argv);
int peers(int argc, char **argv);
int handshake(int argc, char **argv);
int download_piece(int argc, char **argv);
int hash(int argc, char **argv);
int parse(int argc, char **argv);

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
