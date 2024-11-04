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

#define BENCODE_H_VERSION_MAJOR 3
#define BENCODE_H_VERSION_MINOR 0
#define BENCODE_H_VERSION_PATCH 0

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
    const uint8_t *start;
    const uint8_t *end;
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

// end is pointer to end of bytes (if NULL then set to `bencoded_value + strlen(bencoded_value)`)
BencodedValue *decode_bencoded_bytes(const uint8_t *bencoded_value, const uint8_t *end);
BencodedValue *decode_bencoded_file(const char* fname, bool keep_memory);

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
    if (list->next) {
        free_bencoded_list(list->next);
        free(list->next);
    }
}

void free_bencoded_dict(BencodedDict *dict) {
    if (!dict) return;
    free_bencoded_value(dict->key);
    free_bencoded_value(dict->value);
    if (dict->next) {
        free_bencoded_dict(dict->next);
        free(dict->next);
    }
}

void free_bencoded_value(BencodedValue *value) {
    if (!value) return;
    if (value->data) switch (value->type) {
        case BYTES: free(value->data); break;
        case LIST:
            free_bencoded_list((BencodedList *)value->data);
            free(value->data);
            break;
        case DICT:
            free_bencoded_dict((BencodedDict *)value->data);
            free(value->data);
            break;

        case INTEGER: break;
        case UNKNOWN: break;
    }
    free(value);
}

BencodedValue *decode_bencoded_bytes(const uint8_t* bencoded_value, const uint8_t*end) {
    if (end == NULL) end = bencoded_value + strlen((char *)bencoded_value);
    char first = bencoded_value[0];
    switch (first) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9': {
            size_t length = first - '0';
            const uint8_t *p = bencoded_value + 1;
            while (p && p < end && *p != ':') {
                if (10 * length + (*p - '0') < length) {
                    // overflow
                    return NULL;
                }
                length = 10 * length + (*p - '0');
                p ++;
            }
            if (!p || p >= end || *p != ':') {
                fprintf(stderr, "Expected : after byte count\n");
                return NULL;
            }
            if (length > (size_t)(end - p)) {
                fprintf(stderr, "Expected %lu bytes after colon, found %lu bytes\n",
                        length, end - p);
                return NULL;
            }
            const uint8_t* start = p + 1;
            void *data = malloc(length);
            if (!data) return NULL;
            memcpy(data, start, length);
            BencodedValue *ret = calloc(1, sizeof(BencodedValue));
            if (ret == NULL) {
                free(data);
                return NULL;
            }
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
            while (str && str < end && *str != 'e') {
                size ++;
                l->value = decode_bencoded_bytes(str, end);
                if (!l->value || l->value->type == UNKNOWN) {
                    free_bencoded_list(data);
                    free(data);
                    return NULL;
                }
                str = l->value->end;
                if (str && str < end && *str != 'e') {
                    l->next = calloc(1, sizeof(BencodedList));
                    if (!l->next) {
                        fprintf(stderr, "Out of memory\n");
                        free_bencoded_list(data);
                        free(data);
                        return NULL;
                    }
                    l = l->next;
                }
            }
            // FIXME assert missing e?
            BencodedValue *ret = calloc(1, sizeof(BencodedValue));
            if (ret == NULL) {
                free_bencoded_list(data);
                free(data);
                return ret;
            }
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
            while (str && str < end && *str != 'e') {
                size ++;

                d->key = decode_bencoded_bytes(str, end);
                if (!d->key || d->key->type != BYTES) {
                    free_bencoded_dict(data);
                    free(data);
                    return NULL;
                }
                str = d->key->end;
                if (!str || str >= end || *str == 'e') {
                    fprintf(stderr, "Out of memory\n");
                    free_bencoded_dict(data);
                    free(data);
                    return NULL;
                }

                d->value = decode_bencoded_bytes(str, end);
                if (!d->value || d->value->type == UNKNOWN) {
                    free_bencoded_dict(data);
                    free(data);
                    return NULL;
                }
                str = d->value->end;

                if (str && str < end && *str != 'e') {
                    d->next = calloc(1, sizeof(BencodedDict));
                    if (!d->next) {
                        fprintf(stderr, "Out of memory\n");
                        free_bencoded_dict(data);
                        free(data);
                        return NULL;
                    }
                    d = d->next;
                }
            }
            // FIXME assert missing e?
            BencodedValue *ret = calloc(1, sizeof(BencodedValue));
            if (ret == NULL) {
                free_bencoded_dict(data);
                free(data);
                return NULL;
            }
            ret->type = DICT;
            ret->start = bencoded_value;
            ret->end = str + 1;
            ret->size = size;
            ret->data = data;
            return ret;
        }; break;

    }

    fprintf(stderr, "Invalid bencoded data\n");
    return NULL;
}

BencodedValue *decode_bencoded_file(const char* fname, bool keep_memory) {
    BencodedValue *ret = NULL;
    FILE *f = fopen(fname, "rb");
    if (f == NULL) goto end;

    if (fseek(f, 0, SEEK_END) != 0) goto end;
    long fsize = ftell(f);
    if (fsize < 0) goto end;
    if (fseek(f, 0, SEEK_SET) != 0) goto end;

    uint8_t *data = (uint8_t *)malloc(fsize + 1);
    size_t read_total = 0;
    while (read_total < (unsigned)fsize) {
        size_t read_count = fread(data, 1, fsize, f);
        if (read_count == 0) goto end;
        read_total += read_count;
    }
    data[fsize] = 0;

    ret = decode_bencoded_bytes(data, data + fsize);
end:
    if (ret == NULL || (!keep_memory && data)) free(data);
    if (f) fclose(f);
    return ret;
}

int print_bencoded_value(BencodedValue *value, BencodedPrintConfig config) {
    switch (value->type) {
        case UNKNOWN: return EX_DATAERR;
        case BYTES: {
            if (!config.noquotes) printf("\"");
            for (size_t idx = 0; idx < value->size; idx ++) {
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
