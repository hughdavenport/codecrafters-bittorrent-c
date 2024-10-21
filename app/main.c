#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sysexits.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

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
                    printf("\\x%02x", ((char*)value->data)[idx]);
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

    ret = EX_OK;

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
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return EX_USAGE;
    }

    UNREACH
    return EX_SOFTWARE;
}
