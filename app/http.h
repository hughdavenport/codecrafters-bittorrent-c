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

#ifndef HTTP_H
#define HTTP_H

#define HTTP_H_VERSION_MAJOR 1
#define HTTP_H_VERSION_MINOR 1
#define HTTP_H_VERSION_PATCH 1
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define HTTP_H_VERSION_MAJOR_S TOSTRING(HTTP_H_VERSION_MAJOR)
#define HTTP_H_VERSION_MINOR_S TOSTRING(HTTP_H_VERSION_MINOR)
#define HTTP_H_VERSION_PATCH_S TOSTRING(HTTP_H_VERSION_PATCH)
#define HTTP_H_VERSION HTTP_H_VERSION_MAJOR_S "." HTTP_H_VERSION_MINOR_S "." HTTP_H_VERSION_PATCH_S

#define DEPENDS_URL_H_VERSION_MAJOR 1
#define DEPENDS_URL_H_VERSION_MINOR 0
#define DEPENDS_URL_H_VERSION_PATCH 1
#define DEPENDS_URL_H_VERSION \
    TOSTRING(DEPENDS_URL_H_VERSION_MAJOR) "." \
    TOSTRING(DEPENDS_URL_H_VERSION_MINOR) "." \
    TOSTRING(DEPENDS_URL_H_VERSION_PATCH)

#if !defined(URL_H) || !defined(URL_H_VERSION_MAJOR) || !defined(URL_H_VERSION_MINOR) || !defined(URL_H_VERSION_PATCH)
#error "Depends on url.h. You can download this from https://github.com/hughdavenport/url.h"
#elif URL_H_VERSION_MAJOR < DEPENDS_URL_H_MAJOR || \
    (URL_H_VERSION_MAJOR == DEPENDS_URL_H_MAJOR && URL_H_VERSION_MINOR < DEPENDS_URL_H_MINOR) || \
    (URL_H_VERSION_MAJOR == DEPENDS_URL_H_MAJOR && URL_H_VERSION_MINOR == DEPENDS_URL_H_MINOR && URL_H_VERSION_PATCH < DEPENDS_URL_H_PATCH)
#error "Depends on url.h version " DEPENDS_URL_H_VERSION ". You can download this from https://github.com/hughdavenport/url.h"
#endif // !defined(URL_H)

#include <stdbool.h>
#include <unistd.h>

#define HTTP_H_DEFAULT_USER_AGENT \
    "http.h (https://github.com/hughdavenport/http.h " HTTP_H_VERSION ")"

typedef struct {
    const char *name;
    const char *value;
    // FIXME more stuff from spec
} HttpCookie;

typedef struct {
    size_t size;
    size_t capacity;
    HttpCookie *cookies;
} HttpCookieJar;

typedef struct {
    const char *name;
    const char *value;
} HttpHeader;

typedef struct {
    size_t size;
    size_t capacity;
    HttpHeader *data;
} HttpHeaders;

typedef struct {
    const char *name;
    HttpCookieJar *cookie_jar;
} HttpUserAgent;

typedef struct {
    uint16_t status_code;
    char *status_message;
    HttpHeaders *headers;
    size_t content_length;
    uint8_t *body;
} HttpResponse;

int is_http_token_delimiter(char c);

#ifdef HTTP_FUZZ
bool fuzz_http_response(int sock, HttpResponse *response);
#endif // HTTP_FUZZ

/*
 * Send a HTTP request to the supplied URL.
 * - `agent` is used to set the `User-Agent` header, the `Cookie` header, and manage the cookie entries
 * - `headers` are optional headers to send (apart from `Host`, `User-Agent`, and `Accept`)
 * - `response` stores the HTTP response, with a true/false return
 */
bool send_http_request(URL *url, HttpUserAgent *agent, HttpHeaders *headers, HttpResponse *response);

#define HTTP_HEADER(name, value) (name), (value)
// HttpHeaders *build_http_headers(HTTP_HEADER *);
#define build_http_headers(...) _build_http_headers(NULL, __VA_ARGS__, NULL)
// bool add_http_headers(HttpHeaders *headers, HTTP_HEADER *);
#define add_http_headers(headers, ...) _add_http_headers(headers, NULL, __VA_ARGS__, NULL)



void free_http_response(HttpResponse *response);
void free_http_headers(HttpHeaders *headers);

#endif // HTTP_H

#ifdef HTTP_IMPLEMENTATION

#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>

int is_http_token_delimiter(char c) {
    // RFC 9110 5.6.2
    return index("\"(),/:;<=>?@[\\]{}", c) != NULL;
}

char *read_line(char *start, char *end, char **ret) {
    if (start >= end) return NULL;
    char *p = start;
    while (p < end && *p != '\r') {
        if (*p == '\n') {
            fprintf(stderr, "Expected \\r before \\n.\n");
            return NULL;
        }
        p++;
    }
    if (p >= end) {
        *ret = start;
        return p;
    }
    if (p + 1 >= end || *(p + 1) != '\n') {
        fprintf(stderr, "Expected \\n after \\r\n");
        return NULL;
    }
    *p = 0;
    *ret = start;
    return p + 2 >= end ? p + 1 : p + 2;
}

void _send_http_request(int sock, URL *url, HttpUserAgent *agent, HttpHeaders *headers) {
    dprintf(sock, "GET /");
    if (url->path) dprintf(sock, "%s", url->path);
    if (url->query) dprintf(sock, "?%s", url->query);
    dprintf(sock, " HTTP/1.0\r\n");

    // FIXME: This should have port, but only if present
    dprintf(sock, "Host: %s\r\n", url->host);
    if (agent && agent->name) {
        dprintf(sock, "User-Agent: %s\r\n", agent->name);
    } else {
        dprintf(sock, "User-Agent: %s\r\n", HTTP_H_DEFAULT_USER_AGENT);
    }
    dprintf(sock, "Accept: */*\r\n");

    if (agent && agent->cookie_jar && agent->cookie_jar->size > 0) {
        dprintf(sock, "Cookie: ");
        for (size_t idx = 0; idx < agent->cookie_jar->size; idx ++) {
            HttpCookie cookie = agent->cookie_jar->cookies[idx];
            bool valid = true;
            for (const char *p = cookie.name; p && *p; p++) {
                // RFC 6265 S4.2.1 and S4.1.1  - A cookie name is a token
                // RFC 9110 S5.6.2  - Token definition (obsoletes RFC 2616 S2.2)
                if (iscntrl(*p)) {
                    fprintf(stderr, "Cookie contained control character 0x%02x", *p);
                    valid = false;
                    break;
                }
                if (isspace(*p)) {
                    fprintf(stderr, "Cookie contained whitespace 0x%02x", *p);
                    valid = false;
                    break;
                }
                if (is_http_token_delimiter(*p)) {
                    fprintf(stderr, "Cookie contained separator character '%c'", *p);
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;
            for (const char *p = cookie.value; p && *p; p++) {
                // RFC 6265 S4.2.1 and S4.1.1  - A cookie value is a set of octects
                if (iscntrl(*p)) {
                    fprintf(stderr, "Cookie %s contained control character 0x%02x", cookie.name, *p);
                    valid = false;
                    break;
                }
                if (index("\",;\\", *p) != NULL) {
                    fprintf(stderr, "Cookie %s contained invalid character '%c'", cookie.name, *p);
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;
            if (idx != 0) dprintf(sock, "; ");
            dprintf(sock, "%s=%s", cookie.name, cookie.value);
        }
        dprintf(sock, "\r\n");
    }

    // FIXME detect overlap with headers supplied and the above
    if (headers && headers->data && headers->size > 0) {
        for (size_t idx = 0; idx < headers->size; idx ++) {
            HttpHeader header = headers->data[idx];
            bool valid = true;
            for (const char *p = header.name; p && *p; p++) {
                // RFC 9110 S6.3  - A header is a field
                // RFC 9110 S5.1  - A `field-name`, which is a `token`
                // RFC 9110 S5.6.2  - Token definition (obsoletes RFC 2616 S2.2)
                if (iscntrl(*p)) {
                    fprintf(stderr, "Header contained control character 0x%02x\n", *p);
                    valid = false;
                    break;
                }
                if (is_http_token_delimiter(*p)) {
                    fprintf(stderr, "Header contained separator character '%c'\n", *p);
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;
            for (const char *p = header.value; p && *p; p++) {
                // RFC 9110 S6.3  - A header is a field
                // RFC 9110 S5.5  - A header value can be a bunch
                if (!isgraph(*p) && index(" \t", *p) != NULL) {
                    fprintf(stderr, "Header %s contained invalid character 0x%02x\n", header.name, *p);
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;
            dprintf(sock, "%s: %s\r\n", header.name, header.value);
        }
    }

    // Terminating new line
    dprintf(sock, "\r\n");
}

bool _read_http_response(int sock, HttpResponse *response) {
    if (response == NULL) return false;
    bool ret = false;
#define HTTP_BUF_SIZE 4096
    uint8_t buf[HTTP_BUF_SIZE + 1]; // FIXME: This is just on stack, and a limited size. May need to allocate if larger responses
    int len = read(sock, buf, HTTP_BUF_SIZE);
    if (len <= 0) {
        fprintf(stderr, "Could not read from socket\n");
        return false;
    }
    char *p = (char *)buf;
    char *line = NULL;
    char *end = (char*)buf + len;
    *end = 0; // for <strings.h> stuff

    response->headers = calloc(1, sizeof(HttpHeaders));
    if (response->headers == NULL) {
        fprintf(stderr, "Could not allocate %ld bytes for http response headers\n", sizeof(HttpHeaders));
        goto cleanup;
    }

    p = read_line(p, end, &line);
    if (p == NULL) goto cleanup;
    char *space = index(line, ' ');
    if (space == NULL || strncmp(line, "HTTP/", strlen("HTTP/")) != 0) {
        fprintf(stderr, "Wrong protocol recieved: %s\n", line);
        goto cleanup;
    }
    if (strncmp(line + strlen("HTTP/"), "1.", strlen("1.")) != 0) {
        *space = 0;
        fprintf(stderr, "Wrong HTTP version %s\n", (line + strlen("HTTP/")));
        *space = ' ';
        goto cleanup;
    }
    *space = 0;
    if (strcmp(line + strlen("HTTP/1."), "0") != 0) {
        fprintf(stderr, "Different HTTP minor version %s\n", (line + strlen("HTTP/")));
    }
    *space = ' ';

    char *status = space + 1;
    while (*status == ' ') status ++;
    space = index(status, ' ');
    if (space == NULL) {
        fprintf(stderr, "Could not find status code: %s\n", line);
        goto cleanup;
    }
    *space = 0;
    response->status_code = atoi((char *)status);
    *space = ' ';
    response->status_message = strdup((char *)space + 1);
    if (response->status_message == NULL) {
        fprintf(stderr, "Could not allocate %ld bytes for http status message\n", strlen((char *)space + 1));
        goto cleanup;
    }

    // FIXME: read more?
    bool body = false;
    while ((p = read_line(p, end, &line))) {
        if (*line == 0) {
            body = true;
            break;
        }
        char *colon = index(line, ':');
        if (colon == NULL) {
            fprintf(stderr, "Header value didn't have expected `:`.\n");
            goto cleanup;
        }
        *colon = 0;
        if (strncasecmp(line, "Content-Length", strlen("Content-Length")) == 0) {
            long content_length = atol(colon + 1);
            if (content_length < 0) {
                fprintf(stderr, "Negative content-length %ld\n", content_length);
                goto cleanup;
            }
            response->content_length = content_length;
            fprintf(stderr, "Content-Length: %ld\n", response->content_length);
        }
        *colon = ':';
    }

    if (!body) {
        fprintf(stderr, "Could not read all headers from buffer\n");
        goto cleanup;
    }

    if (response->content_length == 0) {
        fprintf(stderr, "Could not find Content-Length\n");
        // FIXME select() to find out if more to read?
        response->content_length = (end - p);
    }

    response->body = calloc(response->content_length + 1, sizeof(uint8_t));
    if (response->body == NULL) {
        fprintf(stderr, "Could not allocate %ld bytes for http body\n", response->content_length);
        goto cleanup;
    }
    if (response->content_length > 0 && response->content_length + ((uint8_t *)p - buf) > (unsigned long)len) {
        size_t size = len - ((uint8_t *)p - buf);
        memcpy(response->body, p, size);
        while (size < response->content_length) {
            len = read(sock, response->body + size, response->content_length - size);
            if (len == 0) {
                fprintf(stderr, "Got EOF after %ld bytes with %ld more bytes to go\n", size, response->content_length - size);
                printf("%s", response->body);
                goto cleanup;
            }
            if (len < 0) {
                fprintf(stderr, "Could not read %ld more bytes\n", response->content_length - size);
                goto cleanup;
            }
            fprintf(stderr, "Read %d extra bytes\n", len);
            size += len;
        }
    } else {
        memcpy(response->body, p, response->content_length);
    }

    ret = true;
cleanup:
    if (!ret && response) {
        free_http_response(response);
    }
    return ret;
}

#ifdef HTTP_FUZZ

bool fuzz_http_response(int sock, HttpResponse *response) {
    bool ret = false;
    ret = _read_http_response(sock, response);
    return ret;
}

#endif // HTTP_FUZZ

bool send_http_request(URL *url, HttpUserAgent *agent, HttpHeaders *headers, HttpResponse *response) {
    bool ret = false;

    int sock = connect_url(url);
    if (sock == -1) return false;

    _send_http_request(sock, url, agent, headers);
    ret = _read_http_response(sock, response);

    if (sock != -1) close(sock);
    return ret;
}

bool _add_http_headers(HttpHeaders *headers, void *start, ...) {
    if (start != NULL) {
        fprintf(stderr, "ERROR: _add_http_headers() should not be called directly. Use add_http_headers(headers, ...)\n");
        return NULL;
    }

    va_list args;
    size_t args_count = 0;
    va_start(args, start);
    while (va_arg(args, char *) != NULL) args_count ++;
    va_end(args);

    if (args_count % 2 != 0) {
        fprintf(stderr, "ERROR: add_http_headers() should be called with an even number of arguments. Try using the HTTP_HEADER macro.\n");
        return NULL;
    }

    size_t num_headers = args_count / 2;

    if (headers->size + num_headers >= headers->capacity) {
        size_t new_capacity = 2 * (headers->capacity + num_headers);
        HttpHeader *data = realloc(headers->data, new_capacity * sizeof(HttpHeader));
        if (data == NULL) {
            // old data is untouched
            return false;
        }
        headers->data = data; // Either the same or new (and old data free'd)
        headers->capacity = new_capacity;
    }

    va_start(args, start);
    for (size_t idx = 0; idx < num_headers; idx ++) {
        // FIXME: Do the RFC checks here
        headers->data[headers->size + idx].name = va_arg(args, char *);
        headers->data[headers->size + idx].value = va_arg(args, char *);
    }
    va_end(args);
    headers->size += num_headers;

    return true;
}

void free_http_headers(HttpHeaders *headers) {
    if (!headers) return;
    if (headers->data) {
        free(headers->data);
        headers->data = NULL;
        headers->capacity = 0;
    }
    headers->size = 0;
}

void free_http_response(HttpResponse *response) {
    if (!response) return;
    if (response->status_message) {
        free(response->status_message);
        response->status_message = NULL;
    }
    if (response->headers) {
        free_http_headers(response->headers);
        free(response->headers);
        response->headers = NULL;
    }
    if (response->body) {
        free(response->body);
        response->body = NULL;
        response->content_length = 0;
    }
}

#endif // HTTP_H_IMPLEMENTATION

