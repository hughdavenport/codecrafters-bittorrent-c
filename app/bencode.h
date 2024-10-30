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

#ifndef BENCODE_H
#define BENCODE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <sysexits.h>

typedef enum {
    UNKNOWN,
    BYTES,
    INTEGER,
    LIST,
    DICT,
} BencodedType;

typedef struct {
    BencodedType type;
    const char *start;
    const char *end;
    size_t size;
    void *data;
} BencodedValue;

typedef struct BencodedList {
    struct BencodedList *next;
    BencodedValue *value;
} BencodedList;

typedef struct BencodedDict {
    struct BencodedDict *next;
    BencodedValue *key;
    BencodedValue *value;
} BencodedDict;

typedef struct {
    bool newline;
    bool noquotes;
} BencodedPrintConfig;

void free_bencoded_value(BencodedValue *value);

BencodedValue *decode_bencoded_bytes(const uint8_t* bencoded_value, const uint8_t*end);
BencodedValue *decode_bencoded_file(const char* fname);

int print_bencoded_value(BencodedValue *value, BencodedPrintConfig config);

BencodedValue *bencoded_dict_value(BencodedDict *d, const char* key);

#endif // BENCODE_H

#ifdef BENCODE_IMPLEMENTATION

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void free_bencoded_list(BencodedList *list);
void free_bencoded_dict(BencodedDict *dict);

void free_bencoded_list(BencodedList *list) {
    if (!list) return;
    free_bencoded_value(list->value);
    free_bencoded_list(list->next);
}

void free_bencoded_dict(BencodedDict *dict) {
    if (!dict) return;
    free_bencoded_value(dict->key);
    free_bencoded_value(dict->value);
    free_bencoded_dict(dict->next);
}

void free_bencoded_value(BencodedValue *value) {
    if (!value) return;
    switch (value->type) {
        case BYTES: free(value->data); break;
        case LIST: free_bencoded_list((BencodedList *)value->data); break;
        case DICT: free_bencoded_dict((BencodedDict *)value->data); break;
    }
    free(value);
}

BencodedValue *decode_bencoded_bytes(const uint8_t* bencoded_value, const uint8_t*end) {
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
                              BencodedValue *ret = calloc(1, sizeof(BencodedValue));
                              if (ret == NULL) return NULL;
                              ret->type = BYTES;
                              ret->start = bencoded_value;
                              ret->end = start + length;
                              ret->size = length;
                              ret->data = data;
                              return ret;
                          }; break;

        case 'i': {
                      const uint8_t*str = bencoded_value + 1;
                      size_t num = 0;
                      if (*str == '-') str++;
                      while (str < end && *str != 'e') {
                          num = 10 * num + (*(str++) - '0');
                      }
                      if (bencoded_value[1] == '-') num = -num;
                      // FIXME assert missing e?
                      BencodedValue *ret = calloc(1, sizeof(BencodedValue));
                      if (ret == NULL) return ret;
                      ret->type = INTEGER;
                      ret->start = bencoded_value;
                      ret->end = str + 1;
                      ret->size = num;
                      ret->data = NULL;
                      return ret;
                  }; break;

        case 'l': {
                      const uint8_t*str = bencoded_value + 1;
                      BencodedList *l = calloc(1, sizeof(BencodedList));
                      if (!l) {
                          fprintf(stderr, "Out of memory\n");
                          return NULL;
                      }
                      BencodedList *data = l;
                      size_t size = 0;
                      while (str < end && *str != 'e') {
                          size ++;
                          l->value = decode_bencoded_bytes(str, end);
                          if (!l->value || l->value->type == UNKNOWN) return NULL;
                          str = l->value->end;
                          if (str && *str != 'e') {
                              l->next = calloc(1, sizeof(BencodedList));
                              if (!l->next) {
                                  fprintf(stderr, "Out of memory\n");
                                  return NULL;
                              }
                              l = l->next;
                          }
                      }
                      // FIXME assert missing e?
                      BencodedValue *ret = calloc(1, sizeof(BencodedValue));
                      if (ret == NULL) return ret;
                      ret->type = LIST;
                      ret->start = bencoded_value;
                      ret->end = str + 1;
                      ret->size = size;
                      ret->data = data;
                      return ret;
                  }; break;

        case 'd': {
                      const uint8_t*str = bencoded_value + 1;
                      BencodedDict *d = calloc(1, sizeof(BencodedDict));
                      if (!d) {
                          fprintf(stderr, "Out of memory\n");
                          return NULL;
                      }
                      BencodedDict *data = d;
                      size_t size = 0;
                      while (str < end && *str != 'e') {
                          size ++;

                          d->key = decode_bencoded_bytes(str, end);
                          if (!d->key || d->key->type != BYTES) return NULL;
                          str = d->key->end;

                          d->value = decode_bencoded_bytes(str, end);
                          if (!d->value || d->value->type == UNKNOWN) return NULL;
                          str = d->value->end;

                          if (str < end && *str != 'e') {
                              d->next = calloc(1, sizeof(BencodedDict));
                              if (!d->next) {
                                  fprintf(stderr, "Out of memory\n");
                                  return NULL;
                              }
                              d = d->next;
                          }
                      }
                      // FIXME assert missing e?
                      BencodedValue *ret = calloc(1, sizeof(BencodedValue));
                      if (ret == NULL) return ret;
                      ret->type = DICT;
                      ret->start = bencoded_value;
                      ret->end = str + 1;
                      ret->size = size;
                      ret->data = data;
                      return ret;
                  }; break;

    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
    return NULL;
}

BencodedValue *decode_bencoded_file(const char* fname) {
    BencodedValue *ret = NULL;
    FILE *f = fopen(fname, "rb");
    if (f == NULL) goto end;

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

    ret = decode_bencoded_bytes(data, data + fsize);
end:
    fclose(f);
    return ret;
}

int print_bencoded_value(BencodedValue *value, BencodedPrintConfig config) {
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
            BencodedList *l = (BencodedList *)value->data;
            while (l) {
                if (!l->value) break;
                if (comma) printf(",");
                else comma = true;
                int ret = print_bencoded_value(l->value, config);
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
            BencodedDict *d = (BencodedDict *)value->data;
            while (d) {
                if (!d->key) break;
                if (comma) printf(",");
                else comma = true;
                int ret = print_bencoded_value(d->key, config);
                if (ret != EX_OK) return ret;
                printf(":");
                ret = print_bencoded_value(d->value, config);
                if (ret != EX_OK) return ret;
                d = d->next;
            }
            printf("}");
            if (config.newline) printf("\n");
            return EX_OK;
        }; break;
    }

    fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
    return EX_SOFTWARE;
}

BencodedValue *bencoded_dict_value(BencodedDict *d, const char* key) {
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

#endif // BENCODE_IMPLEMENTATION
