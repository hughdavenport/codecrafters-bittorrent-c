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

#ifndef URL_H
#define URL_H

#define URL_H_VERSION_MAJOR 1
#define URL_H_VERSION_MINOR 0
#define URL_H_VERSION_PATCH 0

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char *scheme;
    char *authority; // will be "//<NULL>" followed by either user or host (whichever is not null in that order)
    char *user;
    char *pass;
    char *host;
    char *port;
    uint16_t port_num;
    char *path;
    char *query;
    char *fragment;
} URL;

int is_url_print(char c);
bool parse_url(char *start, char *end, URL *ret);
int connect_url(URL *url);

#endif // URL_H

#ifdef URL_IMPLEMENTATION

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int is_url_print(char c) {
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
        if (strcmp(ret->scheme, "http") == 0) {
            ret->port = "80";
            ret->port_num = 80;
        } else {
            fprintf(stderr, "Invalid URL. Could not find port\n");
            return false;
        }
    }

    return true;
}

int connect_url(URL *url) {
    struct addrinfo hints = {0};
    struct addrinfo *result, *rp = NULL;
    int ret = -1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    ret = getaddrinfo(url->host, url->port, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return ret;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        ret = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (ret == -1)
            continue;

        if (connect(ret, rp->ai_addr, rp->ai_addrlen) == 0)
            break; // Success

        close(ret);
        ret = -1;
    }

    freeaddrinfo(result);

    return ret; // Either -1, or a file descriptor of a connected socket
}

#endif // URL_IMPLEMENTATION

