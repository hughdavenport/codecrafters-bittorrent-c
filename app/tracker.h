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

#ifndef TRACKER_H
#define TRACKER_H

#define TRACKER_H_VERSION_MAJOR 1
#define TRACKER_H_VERSION_MINOR 0
#define TRACKER_H_VERSION_PATCH 0

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define DEPENDS_BENCODE_H_VERSION_MAJOR 1
#define DEPENDS_BENCODE_H_VERSION_MINOR 0
#define DEPENDS_BENCODE_H_VERSION_PATCH 0
#define DEPENDS_BENCODE_H_VERSION \
    TOSTRING(DEPENDS_BENCODE_H_VERSION_MAJOR) "." \
    TOSTRING(DEPENDS_BENCODE_H_VERSION_MINOR) "." \
    TOSTRING(DEPENDS_BENCODE_H_VERSION_PATCH)

#if !defined(BENCODE_H) || !defined(SHA1_H_VERSION_MAJOR) || !defined(SHA1_H_VERSION_MINOR) || !defined(SHA1_H_VERSION_PATCH)
#error "Depends on bencode.h. You can download this from https://github.com/hughdavenport/bencode.h"
#elif BENCODE_H_VERSION_MAJOR < DEPENDS_SHA1_H_MAJOR || \
    (BENCODE_H_VERSION_MAJOR == DEPENDS_SHA1_H_MAJOR && SHA1_H_VERSION_MINOR < DEPENDS_SHA1_H_MINOR) || \
    (BENCODE_H_VERSION_MAJOR == DEPENDS_SHA1_H_MAJOR && SHA1_H_VERSION_MINOR == DEPENDS_SHA1_H_MINOR && SHA1_H_VERSION_PATCH < DEPENDS_SHA1_H_PATCH)
#error "Depends on bencode.h version " DEPENDS_BENCODE_H_VERSION " or above. You can download this from https://github.com/hughdavenport/bencode.h"
#endif // !defined(BENCODE_H)

#include <sysexits.h>

// Returns peers after making a request to the tracker
int tracker_response(BencodedDict *dict,
        uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        BencodedValue **response);

#endif // TRACKER_H

#ifdef TRACKER_IMPLEMENTATION

bool add_query_string(URL *url,
        uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        size_t uploaded, size_t downloaded, size_t length) {

    char *p = NULL;
    size_t new_size = strlen("info_hash=") + SHA1_DIGEST_BYTE_LENGTH * 3 +
            strlen("&peer_id=") + strlen(PEER_ID) +
            strlen("&port=") + strlen("6881") +
            strlen("&uploaded=") + strlen("&downloaded=") + strlen("&left=") +
            strlen("&compact=1");
#define BUF_SIZE 4096
    char tmp[BUF_SIZE] = {0}; // Overkill
    int ret = snprintf(tmp, BUF_SIZE - 1, "%lu%lu%lu", uploaded, downloaded, length);
    if (ret <= 0) {
        fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
        return false;
    }
    new_size += ret;

    if (url->query) {
        size_t query_string_len = strlen(url->query);
        new_size += query_string_len + 1;
        char *new_query = malloc(new_size + 1);
        if (new_query == NULL) {
            fprintf(stderr, "Could not allocate %ld bytes for query string\n", new_size + 1);
            return false;
        }
        if (snprintf(new_query, query_string_len + 1, "%s&", url->query) != (int)query_string_len + 1) {
            fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
            free(new_query);
            return false;
        }
        url->query = new_query; // Don't free original query, it is most likely part of a larger buffer from parse_url
        p = url->query + query_string_len + 1; // Points at \0 at end of original query
    } else {
        url->query = malloc(new_size + 1);
        if (url->query == NULL) {
            fprintf(stderr, "Could not allocate %ld bytes for query string\n", new_size + 1);
            return false;
        }
        p = url->query;
    }

    ret = snprintf(p, new_size, "info_hash=");
    if (ret <= 0 || ret > (int)new_size) {
        fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
        return false;
    }
    p += ret; new_size -= ret;
    for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        if (!is_url_print(info_hash[idx])) {
            ret = snprintf(p, new_size, "%%%02x", info_hash[idx]);
            if (ret <= 0 || ret > (int)new_size) {
                fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
                return false;
            }
            p += ret; new_size -= ret;
        } else {
            ret = snprintf(p, new_size, "%c", info_hash[idx]);
            if (ret <= 0 || ret > (int)new_size) {
                fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
                return false;
            }
            p += ret; new_size -= ret;
        }
    }

    ret = snprintf(p, new_size,
            "&peer_id=%s&port=%d&uploaded=%lu&downloaded=%lu&left=%lu&compact=1",
            PEER_ID, 6881, uploaded, downloaded, length);
    if (ret <= 0 || ret > (int)new_size) {
        fprintf(stderr, "%s:%d: UNREACHABLE\n", __FILE__, __LINE__);
        return false;
    }
    p += ret; new_size -= ret;

    return true;
}

int tracker_response(BencodedDict *dict,
        uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH],
        BencodedValue **response) {
    int ret = EX_DATAERR;
    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;

    BencodedValue *announce = bencoded_dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;

    URL url = {0};
    if (!parse_url((char *)announce->data,
                (char *)announce->data + announce->size,
                &url)) {
        goto end;
    }

    ret = EX_UNAVAILABLE;
    if (!add_query_string(&url, info_hash, 0, 0, length->size)) {
        goto end;
    }

    ret = EX_UNAVAILABLE;
    HttpResponse http_response = {0};
    if (!send_http_request(&url, NULL, NULL, &http_response)) {
        goto end;
    }

    ret = EX_PROTOCOL;
    if (http_response.status_code != 200) {
        fprintf(stderr, "Non 200 status code: %d\n", http_response.status_code);
        goto end;
    }

    if (http_response.body == NULL) {
        fprintf(stderr, "Could not find HTTP body.\n");
        goto end;
    }

    BencodedValue *tmp = decode_bencoded_bytes(http_response.body, http_response.body + http_response.content_length);
    if (!tmp) goto end;
    if (tmp->type != DICT) goto end;

    *response = tmp;
    ret = EX_OK;
end:
    free(url.query); // Allocated in add_query_string
    free_http_response(&http_response);
    return ret;
}

#endif // TRACKER_IMPLEMENTATION

