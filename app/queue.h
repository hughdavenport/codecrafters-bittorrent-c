#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stddef.h>

/* FIXME allow different lock implementation */
#include <pthread.h>
#define QUEUE_LOCK(q) pthread_mutex_lock(&(q)->lock)
#define QUEUE_UNLOCK(q) pthread_mutex_unlock(&(q)->lock)
#define QUEUE_WAIT(q) pthread_cond_wait(&(q)->has_data, &(q)->lock)
#define QUEUE_BROADCAST(q) pthread_cond_broadcast(&(q)->has_data)

#define QUEUE_LOCK_INIT(q) pthread_mutex_init(&(q)->lock, NULL)
#define QUEUE_LOCK_DESTROY(q) pthread_mutex_destroy(&(q)->lock)
#define QUEUE_COND_INIT(q) pthread_cond_init(&(q)->has_data, NULL)

#include <stdlib.h>
#define QUEUE_ALLOCATOR_MALLOC malloc
#define QUEUE_ALLOCATOR_CALLOC calloc
#define QUEUE_ALLOCATOR_FREE free

#ifndef QUEUE_LOG_DEFAULT
#define QUEUE_LOG_DEFAULT false
#endif

struct QueueNode {
    struct QueueNode *next;
    struct QueueNode *prev;
    void *data;
};

typedef struct {
    size_t size;
    struct QueueNode *head;
    struct QueueNode *tail;
    pthread_mutex_t lock;
    pthread_cond_t has_data;
} Queue;

static bool queue_init(Queue *q);
static void queue_free(Queue *q);
static bool _queue_push(Queue *q, void *data, bool log);
static void *_queue_pop(Queue *q, bool blocking, bool log);

#define QUEUE_LOG(q) do { \
    ELOG_LOCK; \
    ELOG("queue (%p,size=%zu): [", (void *)(q), (q)->size); \
    for (struct QueueNode *tmp = (q)->head; \
            tmp != NULL; tmp = tmp->next) { \
        if (tmp != (q)->head) ELOG_CONTINUE(", "); \
        ELOG_CONTINUE("%p", tmp->data); \
    } \
    ELOG_CONTINUE("]\n"); \
    ELOG_UNLOCK; \
} while (0)

static inline bool queue_init(Queue *q) {
    if (q == NULL) return false;
    if (QUEUE_LOCK_INIT(q) != 0) return false;
    if (q->head != NULL && q->tail != NULL && q->size > 0) return false;
    if (QUEUE_LOCK(q) != 0) return false;
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    QUEUE_UNLOCK(q);
    return true;
}

static inline void queue_free(Queue *q) {
    if (q == NULL) return;
    QUEUE_LOCK(q);
    if (q->head) {
        while (q->head != q->tail) {
            struct QueueNode *tmp = q->head;
            q->head = q->head->next;
            q->head->prev = NULL;
            QUEUE_ALLOCATOR_FREE(tmp);
        }
        QUEUE_ALLOCATOR_FREE(q->head);
    }
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    QUEUE_UNLOCK(q);
}

static inline bool _queue_push(Queue *q, void *data, bool log) {
    bool ret = false;
    if (q == NULL) return false;
    if (QUEUE_LOCK(q) != 0) {
        ERROR("Could not lock queue");
        return false;
    }
    /* FIXME allocate larger buffer to circular buffer? */
    if (q->head == NULL) {
        q->head = QUEUE_ALLOCATOR_CALLOC(1, sizeof(struct QueueNode));
        if (q->head == NULL) {
            ERROR("Could not allocate space for first entry in queue");
            goto unlock;
        }
        q->tail = q->head;
    } else {
        q->head->prev = QUEUE_ALLOCATOR_CALLOC(1, sizeof(struct QueueNode));
        if (q->head->prev == NULL) {
            ERROR("Could not allocate space for new entry in queue");
            goto unlock;
        }
        q->head->prev->next = q->head;
        q->head = q->head->prev;
    }
    q->head->data = data;
    q->size ++;

    ret = true;

    if (QUEUE_BROADCAST(q) != 0) {
        ERROR("Could not broadcast to queue");
        ret = false;
    }

unlock:
    if (log) QUEUE_LOG(q);
    if (QUEUE_UNLOCK(q) != 0) {
        ERROR("Could not unlock queue");
        return false;
    }
    return ret;
}

static inline void *_queue_pop(Queue *q, bool blocking, bool log) {
    void *ret = NULL;
    if (q == NULL) return NULL;
    if (QUEUE_LOCK(q) != 0) {
        ERROR("Could not lock queue");
        return false;
    }
    if (q->head == NULL || q->tail == NULL) {
        if (!blocking) {
            ELOG("Queue is empty\n");
            goto unlock;
        }
        if (blocking) {
            ELOG("Queue is empty, waiting for data\n");
            while (q->head == NULL || q->tail == NULL) {
                if (QUEUE_WAIT(q) != 0) {
                    ERROR("Could not wait on queue");
                    return NULL;
                }
            }
        }
    }
    /* ELOG("critical start\n"); */
    /* if (log) QUEUE_LOG(q); */

    ret = q->tail->data;
    if (q->tail->prev != NULL) {
        q->tail = q->tail->prev;
        QUEUE_ALLOCATOR_FREE(q->tail->next);
        q->tail->next = NULL;
    } else {
        QUEUE_ALLOCATOR_FREE(q->tail);
        q->tail = NULL;
        q->head = NULL;
    }
    q->size --;

    if (log) {
        ELOG("%p\n", ret);
        QUEUE_LOG(q);
    }
unlock:
    if (QUEUE_UNLOCK(q) != 0) {
        perror("Could not unlock queue");
        return NULL;
    }
    return ret;

}

#define queue_pop_blocking(q) _queue_pop((q), true, QUEUE_LOG_DEFAULT)
#define queue_pop(q) _queue_pop((q), false, QUEUE_LOG_DEFAULT)
#define queue_push(q, data) _queue_push((q), (data), QUEUE_LOG_DEFAULT)

#endif /* QUEUE_H */
