#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sysexits.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define SHA1_IMPLEMENTATION
#include "sha1.h"

#define UNREACH \
    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);

typedef enum {
    UNKNOWN,
    BYTES,
    INTEGER,
    LIST,
    DICT,
} Type;

typedef struct {
    Type type;
    const char *start;
    const char *end;
    size_t size;
    void *data;
} Value;

typedef struct List {
    struct List *next;
    Value *value;
} List;

typedef struct Dict {
    struct Dict *next;
    Value *key;
    Value *value;
} Dict;

void free_value(Value *value);

void free_list(List *list) {
    if (!list) return;
    free_value(list->value);
    free_list(list->next);
}

void free_dict(Dict *dict) {
    if (!dict) return;
    free_value(dict->key);
    free_value(dict->value);
    free_dict(dict->next);
}

void free_value(Value *value) {
    if (!value) return;
    switch (value->type) {
        case BYTES: free(value->data); break;
        case LIST: free_list((List *)value->data); break;
        case DICT: free_dict((Dict *)value->data); break;
    }
    free(value);
}

Value *decode_bencode(const char* bencoded_value) {
    char first = bencoded_value[0];
    switch (first) {
        case '0' ... '9': {
                              int length = atoi(bencoded_value);
                              const char* colon_index = strchr(bencoded_value, ':');
                              if (colon_index == NULL) {
                                  fprintf(stderr, "Invalid encoded value: %s\n", bencoded_value);
                                  return NULL;
                              }
                              const unsigned char* start = colon_index + 1;
                              void *data = malloc(length);
                              if (!data) return NULL;
                              memcpy(data, start, length);
                              Value *ret = calloc(1, sizeof(Value));
                              if (ret == NULL) return NULL;
                              ret->type = BYTES;
                              ret->start = bencoded_value;
                              ret->end = start + length;
                              ret->size = length;
                              ret->data = data;
                              return ret;
                          }; break;

        case 'i': {
                      const char *str = bencoded_value + 1;
                      size_t num = 0;
                      if (*str == '-') str++;
                      while (str && *str != 'e') {
                          num = 10 * num + (*(str++) - '0');
                      }
                      if (bencoded_value[1] == '-') num = -num;
                      // FIXME assert missing e?
                      Value *ret = calloc(1, sizeof(Value));
                      if (ret == NULL) return ret;
                      ret->type = INTEGER;
                      ret->start = bencoded_value;
                      ret->end = str + 1;
                      ret->size = num;
                      ret->data = NULL;
                      return ret;
                  }; break;

        case 'l': {
                      const char *str = bencoded_value + 1;
                      List *l = calloc(1, sizeof(List));
                      if (!l) {
                          fprintf(stderr, "Out of memory\n");
                          return NULL;
                      }
                      List *data = l;
                      size_t size = 0;
                      while (str && *str != 'e') {
                          size ++;
                          l->value = decode_bencode(str);
                          if (!l->value || l->value->type == UNKNOWN) return NULL;
                          str = l->value->end;
                          if (str && *str != 'e') {
                              l->next = calloc(1, sizeof(List));
                              if (!l->next) {
                                  fprintf(stderr, "Out of memory\n");
                                  return NULL;
                              }
                              l = l->next;
                          }
                      }
                      // FIXME assert missing e?
                      Value *ret = calloc(1, sizeof(Value));
                      if (ret == NULL) return ret;
                      ret->type = LIST;
                      ret->start = bencoded_value;
                      ret->end = str + 1;
                      ret->size = size;
                      ret->data = data;
                      return ret;
                  }; break;

        case 'd': {
                      const char *str = bencoded_value + 1;
                      Dict *d = calloc(1, sizeof(Dict));
                      if (!d) {
                          fprintf(stderr, "Out of memory\n");
                          return NULL;
                      }
                      Dict *data = d;
                      size_t size = 0;
                      while (str && *str != 'e') {
                          size ++;

                          d->key = decode_bencode(str);
                          if (!d->key || d->key->type != BYTES) return NULL;
                          str = d->key->end;

                          d->value = decode_bencode(str);
                          if (!d->value || d->value->type == UNKNOWN) return NULL;
                          str = d->value->end;

                          if (str && *str != 'e') {
                              d->next = calloc(1, sizeof(Dict));
                              if (!d->next) {
                                  fprintf(stderr, "Out of memory\n");
                                  return NULL;
                              }
                              d = d->next;
                          }
                      }
                      // FIXME assert missing e?
                      Value *ret = calloc(1, sizeof(Value));
                      if (ret == NULL) return ret;
                      ret->type = DICT;
                      ret->start = bencoded_value;
                      ret->end = str + 1;
                      ret->size = size;
                      ret->data = data;
                      return ret;
                  }; break;

    }

    UNREACH; return NULL;
}

typedef struct {
    bool newline;
    bool noquotes;
} PrintConfig;

int print_value(Value *value, PrintConfig config) {
    switch (value->type) {
        case UNKNOWN: return EX_DATAERR;
        case BYTES: {
            if (!config.noquotes) printf("\"");
            for (int idx = 0; idx < value->size; idx ++) {
                if (!isprint(((char*)value->data)[idx])) {
                    printf("\\x%02x", ((unsigned char*)value->data)[idx]);
                } else {
                    printf("%c", ((char*)value->data)[idx]);
                }
            }
            if (!config.noquotes) printf("\"");
            if (config.newline) printf("\n");
            return EX_OK;
        }; break;

        case INTEGER: {
            printf("%ld", value->size);
            if (config.newline) printf("\n");
            return EX_OK;
        }; break;

        case LIST: {
            printf("[");
            bool comma = false;
            List *l = (List *)value->data;
            while (l) {
                if (!l->value) break;
                if (comma) printf(",");
                else comma = true;
                int ret = print_value(l->value, config);
                if (ret != EX_OK) return ret;
                l = l->next;
            }
            printf("]");
            if (config.newline) printf("\n");
            return EX_OK;
        }; break;

        case DICT: {
            printf("{");
            bool comma = false;
            Dict *d = (Dict *)value->data;
            while (d) {
                if (!d->key) break;
                if (comma) printf(",");
                else comma = true;
                int ret = print_value(d->key, config);
                if (ret != EX_OK) return ret;
                printf(":");
                ret = print_value(d->value, config);
                if (ret != EX_OK) return ret;
                d = d->next;
            }
            printf("}");
            if (config.newline) printf("\n");
            return EX_OK;
        }; break;
    }

    UNREACH
        return EX_SOFTWARE;
}

Value *dict_value(Dict *d, const char* key) {
    while (d) {
        if (!d->key || d->key->type != BYTES) return NULL;
        int cmp = strncmp(key, d->key->data, d->key->size);
        if (cmp == 0) {
            return d->value;
        } else if (cmp < 0) {
            break;
        }
        d = d->next;
    }
    return NULL;
}

int info_file(const char *fname) {
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
    Value *decoded = decode_bencode(data);
    if (!decoded) goto end;
    if (decoded->type != DICT) goto end;
    Dict *dict = (Dict *)decoded->data;

    Value *announce = dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;
    printf("Tracker URL: ");
    print_value(announce, (PrintConfig) {.noquotes = true, .newline=true});

    Value *info = dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    Value *length = dict_value((Dict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;
    printf("Length: ");
    print_value(length, (PrintConfig) {.newline = true});

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

    Value *piece_length = dict_value((Dict *)info->data, "piece length");
    if (!piece_length) goto end;
    if (piece_length->type != INTEGER) goto end;
    ret = EX_OK;
    printf("Piece Length: %ld\n", piece_length->size);

    Value *pieces = dict_value((Dict *)info->data, "pieces");
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
    if (decoded) free_value(decoded);
    if (errno) {
        int ret = errno;
        if (f) fclose(f);
        return ret;
    }
    if (f) if (!fclose(f)) return errno;
    return ret;
}

int is_uri_print(char c) {
    if (!isprint(c)) return 0;
    // RFC 3986 section 2.2 Reserved Characters
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '\'':
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case '/':
        case ':':
        case ';':
        case '=':
        case '?':
        case '@':
        case '[':
        case ']':
            return 0;
    }
    return 1;
}

typedef struct {
    char *scheme;
    char *authority; // will be "//<NULL>" followed by either user or host (whichever is not null in that order)
    char *user;
    char *pass;
    char *host;
    char *port;
    int port_num;
    char *path;
    char *query;
    char *fragment;
} URL;

bool parse_url(char *start, char *end, URL *ret) {
    memset(ret, 0, sizeof(URL));

    // scheme : // user : pass @ host : port / path ? query # fragment
    //         (         "authority"          )
    //            ( "userinfo"  )
    // The following are optional
    //  - authority (including pre-// and post-/, but not pre-:)
    //  - userinfo (including post-@, but not pre-//)
    //  - pass (including pre-:)
    //  - query (including pre-?)
    //  - fragment (including pre-#)
    //
    // This function operates on the input range, and will insert null bytes. Fix with the below.
    //  - ':' 3 bytes before ret->host (or 1 byte before ret->authority)
    //  - ':' before ret->path only if ret->host isn't set
    //  - ':' before ret->pass
    //  - '@' before ret->host if ret->user is also set
    //  - ':' before ret->port if ret->host < ret->port < ret->path
    //  - '/' before ret->path if ret->host is also set
    //  - '?' before query
    //  - '#' before fragment

    char *p = start;
    if (end == NULL) end = p + strlen(p);

    ret->scheme = p;
    while (p < end && *p != ':') p ++;
    if (p >= end) {
        fprintf(stderr, "Could not find scheme in URL\n");
        return false;
    }
    *p = 0;
    if (strcmp(ret->scheme, "http") != 0) {
        fprintf(stderr, "Unsupported scheme: %s\n", ret->scheme);
        return false;
    }
    if (p + 1 >= end || *(p + 1) != '/' || *(p + 2) != '/') {
        if (p + 1 >= end) {
            fprintf(stderr, "Invalid URL. Expected authority or path after scheme\n");
            return false;
        }
        ret->path = p + 1;
        p = end;
    } else {
        ret->authority = p + 1;
        p += 3;
    }

    // At the start, this could be a "userpart", or host.
    if (p < end) ret->user = ret->host = p;
loop:
    while (p && p < end) {
        switch (*p) {
            case ':': {
                if (ret->port || ret->pass || ret->path || ret->query) {
                    p++; break;
                }
                for (char *tmp = p + 1; tmp < end; tmp ++) {
                    if (*tmp == '/') {
                        *tmp = 0;
                        if (tmp + 1 < end) ret->path = tmp + 1;
                        break;
                    } else if (!isdigit(*tmp)) {
                        ret->port_num = 0;
                        break;
                    } else {
                        ret->port_num = 10 * ret->port_num + (*tmp - '0');
                    }
                }
                if (ret->port_num > 0) {
                    *p = 0;
                    ret->port = p + 1;
                    p = ret->path; // Either NULL (eof found above, or set to char after /)
                    if (ret->host == NULL) {
                        fprintf(stderr, "Invalid URL. Expected host before path\n");
                        return false;
                    }
                } else {
                    // The first : in "userpart" separates into pass
                    if (!ret->pass && p + 1 < end) {
                        *p = 0;
                        ret->pass = p + 1;
                    }
                    ret->host = NULL;
                    p += 1;
                }
            }; break;

            case '[': { // IPv6 Literal
                if (ret->host != ret->user || ret->path || ret->query) {
                    p++; break;
                }
                ret->host = p;
                while (p < end && *p != ']') p ++;
            }; break;

            case '@': // End "userpart"
                if ((ret->host && ret->host != ret->user) || ret->path || ret->query) {
                    p++; break;
                }
                *p = 0;
                if (p + 1 < end) ret->host = p + 1;
                p += 1;
                break;

            case '/':
                if (ret->path || ret->query) { p++; break; }
                *p = 0;
                if (ret->host == NULL) {
                    fprintf(stderr, "Invalid URL. Expected host before path\n");
                    return false;
                }
                if (p + 1 < end) ret->path = p + 1;
                break;

            case '?':
                if (ret->query) { p++; break; }
                *p = 0;
                if (ret->path == NULL) {
                    fprintf(stderr, "Invalid URL. Expected path before query\n");
                    return false;
                }
                if (p + 1 < end) ret->query = p + 1;
                break;

            case '#':
                if (ret->fragment) { p++; break; }
                *p = 0;
                if (ret->path == NULL) {
                    fprintf(stderr, "Invalid URL. Expected path before fragment\n");
                    return false;
                }
                if (p + 1 < end) ret->fragment = p + 1;

                // No more processing after finding fragment
                p = end;
                break;

            default:
                p++;
        }
    }

    // If we didn't find a '@', then there was no "userpart"
    if (ret->host == ret->user) ret->user = NULL;

    if (ret->authority && (ret->host == NULL || *ret->host == 0)) {
        fprintf(stderr, "Invalid URL. Could not find hostname\n");
        return false;
    }

    if (ret->port_num == 0) {
        if (strcmp(ret->scheme, "http") == 0) ret->port = "80";
        else {
            fprintf(stderr, "Invalid URL. Could not find port\n");
            return false;
        }
    }

    return true;
}

int connect_url(URL *url) {

}

int peers_file(const char *fname) {
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
    Value *decoded = decode_bencode(data);
    if (!decoded) goto end;
    if (decoded->type != DICT) goto end;
    Dict *dict = (Dict *)decoded->data;
    Value *info = dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    Value *length = dict_value((Dict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;

    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    if (!sha1_digest((const uint8_t*)info->start,
                    (info->end - info->start),
                    info_hash)) {;
        goto end;
    }

    Value *announce = dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;

    print_value(announce, (PrintConfig) {.noquotes = true, .newline=true});
    URL url = {0};
    if (!parse_url((char *)announce->data, (char *)announce->data + announce->size, &url)) {
        goto end;
    }

    printf("scheme = %s\n", url.scheme);
    printf("user = %s\n", url.user);
    printf("pass = %s\n", url.pass);
    printf("host = %s\n", url.host);
    printf("port = %s\n", url.port);
    printf("path = %s\n", url.path);
    printf("query = %s\n", url.query);
    printf("fragment = %s\n", url.fragment);

    struct addrinfo hints = {0};
    struct addrinfo *result, *rp = NULL;
    int sfd, s;
    size_t len;
    ssize_t nread;

    /* char buf[BUF_SIZE]; */

    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    printf("%p\n", result);
    ret = getaddrinfo(url.host, url.port, &hints, &result);
    if (ret != 0) {
        goto end;
    }
    printf("%p\n", result);



    /* int sockfd; */
    /* sockfd = socket(AF_INET, SOCK_STREAM, 0); */
    /* if (sockfd == -1) { */
    /*     goto end; */
    /* } */
    /* struct sockaddr_in servaddr; */
    /* bzero(&servaddr, sizeof(servaddr)); */
    /* servaddr.sin_family = AF_INET; */
    /* servaddr.sin_addr.s_addr = AF_INET; */
    /* servaddr.sin_port = 80; */
    /* connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) */

    printf("info_hash=");
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        if (!is_uri_print(info_hash[idx])) {
            printf("%%%02x", info_hash[idx]);
        } else {
            printf("%c", info_hash[idx]);
        }
    }
    const char *peer_id = "AdtLtU86udGzzN5m9GDsBCaGAAQ";
    printf("&peer_id=%s", peer_id);
    printf("&port=%d", 6881);
    printf("&uploaded=%d", 0);
    printf("&downloaded=%d", 0);
    printf("&left=");
    print_value(length, (PrintConfig) {.newline = false});
    printf("&compact=1");
    printf("\n");


end:
    if (decoded) free_value(decoded);
    if (errno) {
        int ret = errno;
        if (f) fclose(f);
        return ret;
    }
    if (f) if (!fclose(f)) return errno;
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
        return EX_USAGE;
    }

    const char* command = argv[1];

    if (strcmp(command, "decode") == 0) {
        const char* encoded_str = argv[2];
        Value *value = decode_bencode(encoded_str);
        if (!value) return EX_DATAERR;
        print_value(value, (PrintConfig) {0});
        printf("\n");
        free_value(value);
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

    UNREACH
    return EX_SOFTWARE;
}
