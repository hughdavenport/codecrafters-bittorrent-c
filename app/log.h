#ifndef LOG_H
#define LOG_H
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>

typedef struct {
    pthread_mutex_t lock;
    FILE *file;
} Logger;

#define LOGGER_INIT(logger, file_arg) do { \
    logger.file = (file_arg); \
    pthread_mutexattr_t attr; \
    if (pthread_mutexattr_init(&attr) != 0) { \
        perror("pthread_mutexattr_init() error"); \
        break; \
    } \
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) { \
        perror("pthread_mutexattr_settype() error"); \
        break; \
    } \
    if (pthread_mutex_init(&logger.lock, &attr) != 0) { \
        perror("pthread_mutex_init() error"); \
        break; \
    } \
} while (0)

#define LOGGER_DESTROY(logger) pthread_mutex_destroy(&logger.lock)

#if defined(__TINYC__) || defined(__GNUC__)
#define LOGGER_LOG(logger, fmt, ...) do { \
    assert(logger.file != NULL && "Logger struct not initialized"); \
    int lock_ret = pthread_mutex_lock(&logger.lock); \
    assert((lock_ret == 0 || lock_ret == EDEADLK) && "Logger struct not initialized"); \
    fprintf(logger.file, "%s:%d: thread %08lx: %s: " fmt, \
            __FILE__, __LINE__, (uintptr_t)pthread_self(), __func__, ##__VA_ARGS__); \
    if (lock_ret == 0) { \
        assert(pthread_mutex_unlock(&logger.lock) == 0); \
    } \
} while (0)
#else
#define LOGGER_LOG(logger, fmt, ...) do { \
    assert(logger.file != NULL && "Logger struct not initialized"); \
    int lock_ret = pthread_mutex_lock(&logger.lock); \
    assert((lock_ret == 0 || lock_ret == EDEADLK) && "Logger struct not initialized"); \
    fprintf(logger.file, "%s:%d: thread %08lx: %s: " fmt, \
            __FILE__, __LINE__, (uintptr_t)pthread_self(), __func__ __VA_OPT__(,) __VA_ARGS__); \
    if (lock_ret == 0) { \
        assert(pthread_mutex_unlock(&logger.lock) == 0); \
    } \
} while (0)
#endif

#define LOGGER_LOCK(logger) do { \
    int lock_ret = pthread_mutex_lock(&logger.lock); \
    assert((lock_ret == 0 || lock_ret == EDEADLK) && "Logger struct not initialized"); \
    fflush(logger.file); \
} while (0)
#if defined(__TINYC__) || defined(__GNUC__)
#define LOGGER_CONTINUE(logger, fmt, ...) fprintf(logger.file, fmt, ##__VA_ARGS__)
#else
#define LOGGER_CONTINUE(logger, fmt, ...) fprintf(logger.file, fmt __VA_OPT__(,) __VA_ARGS__)
#endif
#define LOGGER_UNLOCK(logger) assert(pthread_mutex_unlock(&logger.lock) == 0)

extern Logger __logger_stdout;
#if defined(__TINYC__) || defined(__GNUC__)
#define LOG(fmt, ...) LOGGER_LOG(__logger_stdout, fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...) LOGGER_LOG(__logger_stdout, fmt __VA_OPT__(,) __VA_ARGS__)
#endif
#define LOG_LOCK LOGGER_LOCK(__logger_stdout)
#if defined(__TINYC__) || defined(__GNUC__)
#define LOG_CONTINUE(fmt, ...) LOGGER_CONTINUE(__logger_stdout, fmt, ##__VA_ARGS__)
#else
#define LOG_CONTINUE(fmt, ...) LOGGER_CONTINUE(__logger_stdout, fmt __VA_OPT__(,) __VA_ARGS__)
#endif
#define LOG_UNLOCK LOGGER_UNLOCK(__logger_stdout)

extern Logger __logger_stderr;
#if defined(__TINYC__) || defined(__GNUC__)
#define ELOG(fmt, ...) LOGGER_LOG(__logger_stderr, fmt, ##__VA_ARGS__)
#else
#if defined(__TINYC__) || defined(__GNUC__)
#define ELOG(fmt, ...) LOGGER_LOG(__logger_stderr, fmt, ##__VA_ARGS__)
#else
#define ELOG(fmt, ...) LOGGER_LOG(__logger_stderr, fmt __VA_OPT__(,) __VA_ARGS__)
#endif
#endif
#define ELOG_LOCK LOGGER_LOCK(__logger_stderr)
#if defined(__TINYC__) || defined(__GNUC__)
#define ELOG_CONTINUE(fmt, ...) LOGGER_CONTINUE(__logger_stderr, fmt, ##__VA_ARGS__)
#else
#define ELOG_CONTINUE(fmt, ...) LOGGER_CONTINUE(__logger_stderr, fmt __VA_OPT__(,) __VA_ARGS__)
#endif
#define ELOG_UNLOCK LOGGER_UNLOCK(__logger_stderr)

#if defined(__TINYC__) || defined(__GNUC__)
#define WARNING(fmt, ...) ELOG("WARNING: " fmt "\n", ##__VA_ARGS__)
#define ERROR(fmt, ...) ELOG("ERROR: " fmt "\n", ##__VA_ARGS__)
#else
#define WARNING(fmt, ...) ELOG("WARNING: " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define ERROR(fmt, ...) ELOG("ERROR: " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#endif

#if defined(__TINYC__) || defined(__GNUC__)
#define UNIMPLEMENTED(fmt, ...) do { \
    ELOG("UNIMPLEMENTED: " fmt "\n", ##__VA_ARGS__); \
    abort(); \
} while (0);
#else
#define UNIMPLEMENTED(fmt, ...) do { \
    ELOG("UNIMPLEMENTED: " fmt "\n" __VA_OPT__(,) __VA_ARGS__); \
    abort(); \
} while (0);
#endif
#ifndef UNREACHABLE
#if defined(__TINYC__) || defined(__GNUC__)
#define UNREACHABLE(fmt, ...) do { \
    ELOG("UNREACHABLE: " fmt "\n", ##__VA_ARGS__); \
    abort(); \
} while (0);
#else
#define UNREACHABLE(fmt, ...) do { \
    ELOG("UNREACHABLE: " fmt "\n" __VA_OPT__(,) __VA_ARGS__); \
    abort(); \
} while (0);
#endif
#endif

#endif /* LOG_H */

#ifdef LOG_IMPLEMENTATION
Logger __logger_stdout;
Logger __logger_stderr;
static void __attribute__((constructor)) logger_stdio_init(void) {
    if (__logger_stderr.file == stderr) return; // Already initialised in another thread
    LOGGER_INIT(__logger_stdout, stdout);
    LOGGER_INIT(__logger_stderr, stderr);
}
#endif /* LOG_IMPLEMENTATION */
