#ifndef IO_H
#define IO_H

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

#include "log.h"

#ifndef IO_LOG_DEFAULT
#define IO_LOG_DEFAULT false
#endif

#define IO_LOG(sock, data, length, func_name) do { \
    ELOG_LOCK; \
    ELOG("%s data (fd=%d, length=%zu):", func_name, sock, length); \
    size_t bytes = length > 16 ? 16 : length; \
    for (size_t idx = 0; idx < bytes; idx ++) { \
        if (idx % 2 == 0) ELOG_CONTINUE(" "); \
        ELOG_CONTINUE("%02x", ((uint8_t*)data)[idx]); \
    } \
    if (length != bytes) ELOG_CONTINUE("[...]"); \
    ELOG_CONTINUE("\n"); \
    ELOG_UNLOCK; \
} while (0)

typedef ssize_t (*io_func_t)(int sock, void *data, size_t length);

static inline bool io_full_length(int sock, void *data, size_t length, io_func_t func, const char *func_name, bool log) {
    ssize_t bytes = 0;
    while ((size_t)bytes < length) {
        ssize_t ret = func(sock, (uint8_t *)data + bytes, length - bytes);
        if (ret <= 0) {
            if (ret < 0) ERROR("%s failed", func_name);
            ERROR("Could only %s %lu bytes out of %lu (fd=%d)", func_name, bytes, length, sock);
            return false;
        }
        bytes += ret;
    }
    if (log && bytes > 0 && (size_t)bytes == length) IO_LOG(sock, data, length, func_name);
    return true;
}

#define _read_full_length(sock, data, length, log) io_full_length(sock, data, length, read, "read", log)
#define _write_full_length(sock, data, length, log) io_full_length(sock, data, length, (io_func_t) write, "write", log)
#define read_full_length(sock, data, length) _read_full_length(sock, data, length, IO_LOG_DEFAULT)
#define write_full_length(sock, data, length) _write_full_length(sock, data, length, IO_LOG_DEFAULT)

#define read_full(sock, thing) read_full_length(sock, &(thing), sizeof((thing)))
#define write_full(sock, thing) write_full_length(sock, &(thing), sizeof((thing)))

#define DRAIN(sock, size) while ((size) > 0) { \
        uint8_t tmp; \
        if (_read_full_length((sock), &tmp, 1, false)) (size) --; \
    }

#endif // IO_H
