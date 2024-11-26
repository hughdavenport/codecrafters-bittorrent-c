#ifndef URL_QUERY_H
#define URL_QUERY_H

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t size;
} ByteBuffer;

#define BYTE_BUFFER_REALLOC_SIZE 16


#define byte_buffer_append(buf, b) { \
    if ((buf)->size + 1 > (buf)->capacity) { \
        (buf)->capacity += BYTE_BUFFER_REALLOC_SIZE; \
        (buf)->data = realloc((buf)->data, (buf)->capacity); \
    } \
    (buf)->data[(buf)->size++] = (b); \
}
#define byte_buffer_reset(buf) { \
    (buf)->size = 0; \
    (buf)->capacity = 0; \
    if ((buf)->data) { \
        free((buf)->data); \
        (buf)->data = NULL; \
    } \
}

#define cstr_to_byte_buffer(str) (ByteBuffer){ \
    .data = (uint8_t *)(str), \
    .size = strlen(str), \
}

typedef struct {
    ByteBuffer name;
    ByteBuffer value;
    ByteBuffer *data;
    size_t capacity;
    size_t size;
} URLQueryParameter;

typedef struct {
    URLQueryParameter **data;
    size_t capacity;
    size_t size;
} URLQueryParameters;

#define pointer_buffer_append(buf, p) { \
    if ((buf)->size + sizeof((p)) > (buf)->capacity) { \
        (buf)->capacity += sizeof((p)) * BYTE_BUFFER_REALLOC_SIZE; \
        (buf)->data = realloc((buf)->data, (buf)->capacity); \
    } \
    (buf)->data[(buf)->size++] = (p); \
}
#define url_query_parameters_append pointer_buffer_append

bool url_parse_query(const URL *url, URLQueryParameters *parameters);
URLQueryParameter *url_query_parameter(const URLQueryParameters *parameters, const ByteBuffer *name);
void free_url_query_parameters(const URLQueryParameters *parameters);
bool byte_buffer_copy(ByteBuffer *dest, ByteBuffer *src);

#endif

#ifdef URL_QUERY_IMPLEMENTATION
#include <string.h>
#include <ctype.h>

bool byte_buffer_copy(ByteBuffer *dest, ByteBuffer *src) {
    dest->data = malloc(src->size + 1);
    if (dest->data == NULL) return false;
    dest->size = src->size;
    dest->capacity = src->size;
    memcpy(dest->data, src->data, src->size);
    dest->data[src->size] = 0;
    return true;
}

bool url_parse_query(const URL *url, URLQueryParameters *parameters) {
    if (url == NULL || parameters == NULL) return false;
    char *query = url->query;
    char *p = query;
    ByteBuffer buf = {0};
    URLQueryParameter *cur = NULL;
    while (*p) {
        switch (*p) {
            case '%': {
                char c1 = *(p+1);
                if (c1 == 0) return false;
                char c2 = *(p+2);
                if (c2 == 0) return false;
                if (!isxdigit(c1) || !isxdigit(c2)) return false;
                c1 = tolower(c1);
                c2 = tolower(c2);
                uint8_t b = 0;
                if (isdigit(c1)) b += c1 - '0';
                else b += 10 + c1 - 'a';
                b *= 16;
                if (isdigit(c2)) b += c2 - '0';
                else b += 10 + c2 - 'a';
                byte_buffer_append(&buf, b);
                p += 3;
                continue;
            }; fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__); break;

            case '&': {
                if (cur != NULL) {
                    if (cur->size == 0) {
                        if (!byte_buffer_copy(&cur->value, &buf)) return false;
                        cur->size = 1;
                    } else if (cur->size == 1) {
                        cur->capacity = BYTE_BUFFER_REALLOC_SIZE;
                        cur->data = calloc(cur->capacity, sizeof(ByteBuffer));
                        if (cur->data == NULL) return false;
                        cur->size = 2;
                        if (!byte_buffer_copy(&cur->data[0], &cur->value)) return false;
                        if (!byte_buffer_copy(&cur->data[1], &buf)) return false;
                        byte_buffer_reset(&cur->value);
                    } else {
                        if (cur->size + 1 > cur->capacity) {
                            cur->capacity += BYTE_BUFFER_REALLOC_SIZE;
                            cur->data = realloc(cur->data, sizeof(ByteBuffer) * cur->capacity);
                        }
                        if (!byte_buffer_copy(&cur->data[cur->size++], &buf)) return false;
                    }
                } else {
                    cur = url_query_parameter(parameters, &buf);
                    if (cur == NULL) {
                        cur = (URLQueryParameter*)calloc(1, sizeof(URLQueryParameter));
                        if (cur == NULL) return false;
                        if (!byte_buffer_copy(&cur->name, &buf)) return false;
                    } else {
                        if (cur->size == 0) {
                            if (!byte_buffer_copy(&cur->value, &buf)) return false;
                            cur->size = 1;
                        } else if (cur->size == 1) {
                            cur->capacity = BYTE_BUFFER_REALLOC_SIZE;
                            cur->data = calloc(cur->capacity, sizeof(ByteBuffer));
                            if (cur->data == NULL) return false;
                            cur->size = 2;
                            if (!byte_buffer_copy(&cur->data[0], &cur->value)) return false;
                            if (!byte_buffer_copy(&cur->data[1], &buf)) return false;
                            byte_buffer_reset(&cur->value);
                        } else {
                            if (cur->size + 1 > cur->capacity) {
                                cur->capacity += BYTE_BUFFER_REALLOC_SIZE;
                                cur->data = realloc(cur->data, sizeof(ByteBuffer) * cur->capacity);
                            }
                            if (!byte_buffer_copy(&cur->data[cur->size++], &buf)) return false;
                        }
                    }
                }

                if (cur != NULL) {
                    if (url_query_parameter(parameters, &cur->name) == NULL) {
                        url_query_parameters_append(parameters, cur);
                    }
                }
                cur = NULL;
                byte_buffer_reset(&buf);
            }; break;

            case '=': {
                cur = url_query_parameter(parameters, &buf);
                if (cur == NULL) {
                    cur = (URLQueryParameter*)calloc(1, sizeof(URLQueryParameter));
                    if (cur == NULL) return false;
                    if (!byte_buffer_copy(&cur->name, &buf)) return false;
                }
                byte_buffer_reset(&buf);
            }; break;

            default:
                byte_buffer_append(&buf, *(uint8_t *)p);
        }
        p++;
    }

    if (cur != NULL) {
        if (cur->size == 0) {
            if (!byte_buffer_copy(&cur->value, &buf)) return false;
            cur->size = 1;
        } else if (cur->size == 1) {
            cur->capacity = BYTE_BUFFER_REALLOC_SIZE;
            cur->data = calloc(cur->capacity, sizeof(ByteBuffer));
            if (cur->data == NULL) return false;
            cur->size = 2;
            if (!byte_buffer_copy(&cur->data[0], &cur->value)) return false;
            if (!byte_buffer_copy(&cur->data[1], &buf)) return false;
            byte_buffer_reset(&cur->value);
        } else {
            if (cur->size + 1 > cur->capacity) {
                cur->capacity += BYTE_BUFFER_REALLOC_SIZE;
                cur->data = realloc(cur->data, sizeof(ByteBuffer) * cur->capacity);
            }
            if (!byte_buffer_copy(&cur->data[cur->size++], &buf)) return false;
        }
    } else {
        cur = url_query_parameter(parameters, &buf);
        if (cur == NULL) {
            cur = (URLQueryParameter*)calloc(1, sizeof(URLQueryParameter));
            if (cur == NULL) return false;
            if (!byte_buffer_copy(&cur->name, &buf)) return false;
        } else {
            if (cur->size == 0) {
                if (!byte_buffer_copy(&cur->value, &buf)) return false;
                cur->size = 1;
            } else if (cur->size == 1) {
                cur->capacity = BYTE_BUFFER_REALLOC_SIZE;
                cur->data = calloc(cur->capacity, sizeof(ByteBuffer));
                if (cur->data == NULL) return false;
                cur->size = 2;
                if (!byte_buffer_copy(&cur->data[0], &cur->value)) return false;
                if (!byte_buffer_copy(&cur->data[1], &buf)) return false;
                byte_buffer_reset(&cur->value);
            } else {
                if (cur->size + 1 > cur->capacity) {
                    cur->capacity += BYTE_BUFFER_REALLOC_SIZE;
                    cur->data = realloc(cur->data, sizeof(ByteBuffer) * cur->capacity);
                }
                if (!byte_buffer_copy(&cur->data[cur->size++], &buf)) return false;
            }
        }
    }

    if (cur != NULL) {
        if (url_query_parameter(parameters, &cur->name) == NULL) {
            url_query_parameters_append(parameters, cur);
        }
    }
    cur = NULL;
    byte_buffer_reset(&buf);

    return true;
}

URLQueryParameter *url_query_parameter(const URLQueryParameters *parameters, const ByteBuffer *name) {
    if (parameters == NULL || name == NULL) return NULL;
    for (size_t idx = 0; idx < parameters->size; idx ++) {
        URLQueryParameter *param = parameters->data[idx];
        if (param == NULL) continue;
        if (param->name.size != name->size) continue;
        if (memcmp(param->name.data, name->data, name->size) != 0) continue;
        return param;
    }
    return NULL;
}

void free_url_query_parameters(const URLQueryParameters *parameters) {
    if (parameters == NULL || parameters->data == NULL) return;
    for (size_t idx = 0; idx < parameters->size; idx ++) {
        URLQueryParameter *param = parameters->data[idx];
        if (param == NULL) continue;
        if (param->name.data) free(param->name.data);
        if (param->value.data) free(param->value.data);
        if (param->data != NULL) {
            for (size_t b_idx = 0; b_idx < param->size; b_idx ++) {
                if (param->data[b_idx].data) {
                    free(param->data[b_idx].data);
                }
            }
            free(param->data);
        }
        free(param);
    }
    free(parameters->data);
}
#endif
