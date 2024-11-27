// FIXME make this into header only job queue library



#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "sha1.h"
#include "url.h"
#include "url-query.h"
#include "bencode.h"
#include "tracker.h"
#include "peers.h"

#include "log.h"
#include "queue.h"

pthread_mutex_t print_lock;
struct JobList;
typedef struct Job {
    void *(*func)(struct JobList *jobs, void *data);
    void *data;
    bool (*callback)(struct JobList *jobs, void *data);
    ssize_t id;
} Job;

#define array_add(array, item) do { \
    if ((array).data == NULL) { \
        (array).capacity = 16; \
        (array).data = calloc((array).capacity, sizeof((array).data)); \
    } \
    if ((array).size + 1 >= (array).capacity) { \
        size_t new_capacity = (array).capacity * 2; \
        void *data = realloc((array).data, new_capacity * sizeof((array).data)); \
        assert(data != NULL && "Not enough memory"); \
        (array).data = data; \
        (array).capacity = new_capacity; \
    } \
    (array).data[(array).size++] = (item); \
} while (0);

typedef struct {
    ssize_t id;
    pthread_cond_t cond;
    void *data;
} JobWaiter;

typedef struct JobList {
    ssize_t max_id;
    Queue data;
    struct {
        JobWaiter **data;
        size_t size;
        size_t capacity;
    } waiting;
    pthread_mutex_t lock;
} JobList;

ssize_t job_add(JobList *list, Job *job);
void *job_wait(JobList *list, ssize_t job_id);
Job *job_next(JobList *list);
void job_list_free(JobList *list);

void job_list_init(JobList *list);

void job_list_init(JobList *jobs) {
    queue_init(&jobs->data);
    pthread_mutex_init(&jobs->lock, NULL);
}

void job_list_free(JobList *jobs) {
    queue_free(&jobs->data);
    pthread_mutex_destroy(&jobs->lock);
}

ssize_t job_add(JobList *list, Job *job) {
    if (queue_push(&list->data, (void *)job)) {
        job->id = list->max_id++;
        return job->id;
    }
    return -1;
}

void *job_wait(JobList *list, ssize_t job_id) {
    if (list == NULL || job_id == -1) return NULL;
    /* ELOG("locking\n"); */
    if (pthread_mutex_lock(&list->lock) != 0) {
        perror("pthread_mutex_lock() error");
        return NULL;
    }
    /* ELOG("critical\n"); */
    void *ret = NULL;

    // FIXME what if job already finished and gone?
    JobWaiter waiter = {
        .id = job_id,
    };
    pthread_cond_init(&waiter.cond, NULL);
    array_add(list->waiting, &waiter);
    ELOG("waiting for job id %zi\n", job_id);
    if (pthread_cond_wait(&waiter.cond, &list->lock) != 0) {
        perror("pthread_cond_wait() error");
        goto unlock;
    }
    ret = waiter.data;

unlock:
    /* ELOG("critical end\n"); */
    if (pthread_mutex_unlock(&list->lock) != 0) {
        perror("pthread_mutex_unlock() error");
        return NULL;
    }
    /* ELOG("unlocked\n"); */
    return ret;
}

Job *job_next(JobList *list) {
    if (list == NULL) return NULL;
    return (Job *)queue_pop(&list->data);
}

void job_signal_waiters(JobList *jobs, ssize_t job_id, void *ret) {
    if (jobs == NULL || job_id == -1) return;
    /* ELOG("locking\n"); */
    if (pthread_mutex_lock(&jobs->lock) != 0) {
        perror("pthread_mutex_lock() error");
        return;
    }
    /* ELOG("critical\n"); */
    if (jobs->waiting.size == 0) goto unlock;
    for (size_t idx = jobs->waiting.size - 1; ; idx --) {
        if (jobs->waiting.data[idx]->id == job_id) {
            jobs->waiting.data[idx]->data = ret;
            /* ELOG("broadcasting to %p\n", jobs->waiting.data[idx]->cond); */
            if (pthread_cond_broadcast(&jobs->waiting.data[idx]->cond) != 0) {
                perror("pthread_cond_broadcast() error");
                // FIXME cleanup
                goto unlock;
            }
            break;
        }
        if (idx == 0) break;
    }

unlock:
    /* ELOG("critical end\n"); */
    if (pthread_mutex_unlock(&jobs->lock) != 0) {
        perror("pthread_mutex_unlock() error");
        // FIXME cleanup
        return;
    }
    /* ELOG("unlocked\n"); */
    return;
}


void *job_event_loop(void *data) {
    /* ELOG("(%p)\n", data); */
    ELOG("thread start\n");
    JobList *jobs = (JobList *)data;
    for (Job *job = job_next(jobs); job != NULL; job = job_next(jobs) ) {
        ELOG("got job %zi\n", job->id);
        if (job->func == NULL) break;
        void *ret = job->func(jobs, job->data);
        if (job->callback) {
            ELOG("finished job %zi, sending to callback function\n", job->id);
            if (!job->callback(jobs, ret)) break;
        } else {
            ELOG("finished job %zi\n", job->id);
        }
        job_signal_waiters(jobs, job->id, ret);
    }
    ELOG("thread died\n");
    return NULL;
}


typedef struct {
    char host[17]; // FIXME ip6 addresses?
    char port[6];
} Peer;

typedef struct {
    uint8_t hash[SHA1_DIGEST_BYTE_LENGTH];
    size_t requests_outstanding;
    pthread_mutex_t lock;
    pthread_cond_t complete;
} Piece;

typedef struct {
    pthread_rwlock_t lock;
    char *tracker;
    size_t length;
    uint8_t *data;
    uint8_t info_hash[SHA1_DIGEST_BYTE_LENGTH];
    size_t piece_length;
    size_t num_pieces;
    Piece *pieces;
    Peer *peers;
    size_t num_peers;
    char *name;
    Queue requests;
    // FIXME multi file
} TorrentFile;

#define HANDSHAKE_SIZE 68
#define RESERVED_SIZE 8
#define PEER_ID_SIZE 20
typedef struct {
    int fd;
    bool unchoked;
    bool interested;
    uint8_t peer_id[PEER_ID_SIZE+1];
    uint8_t reserved[RESERVED_SIZE+1];
    TorrentFile *torrent;
    size_t idx;
} PeerConnection;

TorrentFile *parse_magnet_url(const char *data) {
    ELOG("%s\n", data);
    char *magnet_url = strdup((char *)data);
    if (magnet_url == NULL) return NULL;

    bool success = false;
    TorrentFile *ret = calloc(1, sizeof(TorrentFile));
    if (ret == NULL) goto end;
    pthread_rwlock_init(&ret->lock, NULL);

    URL url = {0};
    if (!parse_url(magnet_url, NULL, &url)) goto end;
    if (strcmp(url.scheme, "magnet") != 0) {
        fprintf(stderr, "Expected magnet url\n");
        goto end;
    }
    URLQueryParameters parameters = {0};
    if (!url_parse_query(&url, &parameters)) goto end;
    URLQueryParameter *dn = url_query_parameter(&parameters, &cstr_to_byte_buffer("dn"));
    URLQueryParameter *xt = url_query_parameter(&parameters, &cstr_to_byte_buffer("xt"));
    URLQueryParameter *tr = url_query_parameter(&parameters, &cstr_to_byte_buffer("tr"));
    if (!xt) {
        fprintf(stderr, "Couldn't find `xt` query parameter.\n");
        goto end;
    }
    if (xt->size != 1) {
        fprintf(stderr, "Expected exactly 1 `xt` query parameter.\n");
        goto end;
    }

    if (xt->value.size < 9) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%*s`\n",
                (int)xt->value.size, xt->value.data);
        goto end;
    }
    if (memcmp(xt->value.data, "urn:", 4) != 0) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%4s...`\n",
                xt->value.data);
        goto end;
    }
    char *hash_type = (char *)xt->value.data + 4;
    if (memcmp(hash_type, "btih:", 5) != 0 && memcmp(hash_type, "btmh:", 5) != 0) {
        fprintf(stderr, "Expecting `xt` parameter to start with `urn:btih:` or `urn:btmh:`, but found `%9s...`\n",
                xt->value.data);
        goto end;
    }
    if (memcmp(hash_type, "btmh", 4) == 0) {
        UNIMPLEMENTED("Don't support magnet v2 links, yet.\n");
        goto end;
    }

    char *hash = (char *)xt->value.data + 9;
    if (xt->value.size - 9 != 2 * SHA1_DIGEST_BYTE_LENGTH) {
        if (xt->value.size - 9 != 32) {
            fprintf(stderr, "Expected a 40 char hex encoded or 32 character base32 encoded info hash in `xt`, but got length %ld\n",
                    xt->value.size - 9);

            goto end;
        }
        UNIMPLEMENTED("base32 encoding");
        goto end;
    } else {
        for (size_t idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
            uint8_t c1 = hash[2*idx];
            uint8_t c2 = hash[2*idx + 1];
            if (!isxdigit(c1) || !isxdigit(c2)) {
                fprintf(stderr, "Expected 40 char hex encoded info hash. Found non hex character at idx %zu\n",
                        idx);
                goto end;
            }
            uint8_t d1 = 0, d2 = 0;
            if (isdigit(c1)) {
                d1 = c1 - '0';
            } else {
                d1 = 10 + tolower(c1) - 'a';
            }
            if (isdigit(c2)) {
                d2 = c2 - '0';
            } else {
                d2 = 10 + tolower(c2) - 'a';
            }
            if (d1 > 0xF || d2 > 0xF) {
                UNREACHABLE("%x > 0xF || %x > 0xF", d1, d2);
                goto end;
            }
            ret->info_hash[idx] = d1 << 4 | d2;
        }
    }

    if (tr && (tr->size == 1 || (tr->size > 1 && tr->data))) {
        if (tr->size > 1) {
            UNIMPLEMENTED("multiple trackers");
        } else {
            ret->tracker = strndup((char *)tr->value.data, tr->value.size);
        }
    }

    if (dn && (dn->size == 1 || (dn->size > 1 && dn->data))) {
        if (dn->size > 1) {
            UNIMPLEMENTED("multiple names");
        } else {
            ret->name = strndup((char *)dn->value.data, dn->value.size);
        }
    }

    success = true;
end:
    free(magnet_url);
    free_url_query_parameters(&parameters);
    if (!success && ret) {
        free(ret->name);
        free(ret->tracker);
        free(ret);
        ret = NULL;
    }
    return ret;
}

TorrentFile *parse_torrent_file(const char *torrent_file) {
    ELOG("\"%s\"\n", torrent_file);
    bool success = false;
    TorrentFile *ret = NULL;

    BencodedValue *decoded = decode_bencoded_file(torrent_file, true);
    if (!decoded) goto end;
    if (decoded->type != DICT) goto end;
    BencodedDict *dict = (BencodedDict *)decoded->data;

    ret = calloc(1, sizeof(TorrentFile));
    if (ret == NULL) goto end;
    pthread_rwlock_init(&ret->lock, NULL);
    queue_init(&ret->requests);

    // FIXME logging?

    BencodedValue *announce = bencoded_dict_value(dict, "announce");
    if (!announce) goto end;
    if (announce->type != BYTES) goto end;
    ret->tracker = strndup(announce->data, announce->size);
    if (ret->tracker == NULL) goto end;

    BencodedValue *info = bencoded_dict_value(dict, "info");
    if (!info) goto end;
    if (info->type != DICT) goto end;
    BencodedValue *length = bencoded_dict_value((BencodedDict *)info->data, "length");
    if (!length || length->type != INTEGER) goto end;
    ret->length = length->size;

    if (!sha1_digest((const uint8_t *)info->start,
                (info->end - info->start),
                ret->info_hash)) {
        goto end;
    }

    BencodedValue *piece_length = bencoded_dict_value((BencodedDict *)info->data, "piece length");
    if (!piece_length) goto end;
    if (piece_length->type != INTEGER) goto end;
    ret->piece_length = piece_length->size;

    BencodedValue *pieces = bencoded_dict_value((BencodedDict *)info->data, "pieces");
    if (!pieces) goto end;
    if (pieces->type != BYTES) goto end;
    ret->num_pieces = pieces->size / SHA1_DIGEST_BYTE_LENGTH;
    ret->pieces = calloc(ret->num_pieces, sizeof(Piece));

    for (size_t piece = 0; piece < pieces->size / SHA1_DIGEST_BYTE_LENGTH; piece ++) {
        memcpy(&ret->pieces[piece], &((uint8_t *)pieces->data)[piece * SHA1_DIGEST_BYTE_LENGTH], SHA1_DIGEST_BYTE_LENGTH);
    }

    BencodedValue *name = bencoded_dict_value((BencodedDict *)info->data, "name");
    if (!name) goto end;
    if (name->type != BYTES) goto end;
    ret->name = strndup(name->data, name->size);

    success = true;

end:
    if (decoded) {
        // decoded->start is only valid if `true` is passed to `decode_bencoded_file` to keep memory around
        free((void *)decoded->start);
        free_bencoded_value(decoded);
    }
    if (!success && ret) {
        free(ret->name);
        free(ret->tracker);
        free(ret);
        ret = NULL;
    }
    return ret;
}

TorrentFile *parse_torrent_file_or_magnet(const char *data) {
    if (data == NULL) return NULL;
    if (strncmp(data, "magnet:", strlen("magnet")) == 0) {
        return parse_magnet_url(data);
    } else {
        return parse_torrent_file(data);
    }
}

bool get_peers(TorrentFile *torrent) {
    ELOG("(%p)\n", (void *)torrent);
    bool ret = false;
    if (torrent->tracker == NULL) {
        UNIMPLEMENTED("DHT extension");
        return false;
    }
    if (pthread_rwlock_wrlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_wrlock() error");
        return false;
    }
    if (torrent->peers) goto unlock; // Already done

    URL tracker = {0};
    char *tr = strdup(torrent->tracker);
    if (tr == NULL) UNREACHABLE();
    parse_url(tr, NULL, &tracker);
    BencodedValue *tracker_response = NULL;
    size_t length = torrent->length == 0 ? 1 : torrent->length; // Must be > 0 to get any peers. Exact number not known in advance
    if (tracker_response_from_url(&tracker, 0, 0, length,
                torrent->info_hash, &tracker_response) != EX_OK) {
        free(tr);
        goto unlock;
    }
    free(tr);
    ELOG("(%s)\n", tracker_response->start);
    BencodedValue *peers = bencoded_dict_value((BencodedDict *)tracker_response->data, "peers");
    if (!peers || peers->type != BYTES) goto unlock;
    if (peers->size % 6 != 0) goto unlock;
    torrent->peers = calloc(peers->size, sizeof(Peer));
    if (torrent->peers == NULL) goto unlock;
    torrent->num_peers = peers->size / 6;

    for (size_t idx = 0; (idx + 1) * 6 <= peers->size; idx ++) {
        snprintf(torrent->peers[idx].host, 17, "%d.%d.%d.%d",
                ((uint8_t *)peers->data)[6 * idx + 0],
                ((uint8_t *)peers->data)[6 * idx + 1],
                ((uint8_t *)peers->data)[6 * idx + 2],
                ((uint8_t *)peers->data)[6 * idx + 3]);
        snprintf(torrent->peers[idx].port, 6, "%d",
                256 * ((uint8_t *)peers->data)[6 * idx + 4] +
                ((uint8_t *)peers->data)[6 * idx + 5]);
        ELOG("Got peer %s:%s\n", torrent->peers[idx].host, torrent->peers[idx].port);
    }

    ret = true;
unlock:
    if (torrent && pthread_rwlock_unlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_unlock() error");
        return false;
    }

    return ret;
}

bool get_handshake(PeerConnection *peer) {
    ELOG("(%p)\n", (void *)peer);
    bool ret = false;
    if (peer->torrent == NULL) return -1;
    TorrentFile *torrent = peer->torrent;
    if (pthread_rwlock_rdlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_rdlock() error");
        return false;
    }
    if (torrent->peers == NULL) {
        ELOG("No peers, returning\n");
        goto unlock;
    }
    if (peer->idx >= torrent->num_peers) goto unlock;
    for (size_t cnt = 0; cnt < 5; cnt ++) {
        size_t idx = peer->idx;

        uint8_t response[HANDSHAKE_SIZE];
        ELOG("handshaking with %s:%s\n", torrent->peers[idx].host, torrent->peers[idx].port);
        peer->fd = handshake_peer(torrent->peers[idx].host, torrent->peers[idx].port, torrent->info_hash, response);
        if (peer->fd < 0) {
            ELOG("Failed to handshake to %s:%s%s", torrent->peers[idx].host, torrent->peers[idx].port,
                    cnt == 4 ? "\n" : ", retrying...\n");
            if (cnt == 4) {
                break;
            }
            continue;
        }
        memcpy(peer->reserved,
                response + response[0] + 1,
                RESERVED_SIZE);
        memcpy(peer->peer_id,
                response + response[0] + 1 + RESERVED_SIZE + SHA1_DIGEST_BYTE_LENGTH,
                PEER_ID_SIZE);
        ret = true;
        goto unlock;
    }

unlock:
    if (pthread_rwlock_unlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_unlock() error");
        return false;
    }

    return ret;
}

void info_torrent_file(const char *data) {
    ELOG("(%s)\n", data);
    if (data == NULL) return;
    TorrentFile *torrent = parse_torrent_file_or_magnet(data);
    if (torrent == NULL) return;
    if (pthread_rwlock_rdlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_rdlock() error");
        return;
    }

    if (pthread_mutex_lock(&print_lock) != 0) {
        perror("pthread_mutex_lock() error");
        goto unlock_torrent;
    }

    printf("Tracker URL: %s\n", torrent->tracker);
    if (torrent->length > 0) printf("Length: %zu\n", torrent->length);
    printf("Info Hash: ");
    for (size_t idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
        printf("%02x", torrent->info_hash[idx]);
    }
    printf("\n");
    if (torrent->piece_length > 0) printf("Piece Length: %zu\n", torrent->piece_length);
    if (torrent->num_pieces > 0) {
        printf("Piece Hashes:\n");
        for (size_t piece = 0; piece < torrent->num_pieces; piece ++) {
            for (size_t idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
                printf("%02x", torrent->pieces[piece].hash[idx]);
            }
            printf("\n");
        }
    }

    if (pthread_mutex_unlock(&print_lock) != 0) {
        perror("pthread_mutex_unlock() error");
    }
unlock_torrent:
    if (pthread_rwlock_unlock(&torrent->lock) != 0) {
        perror("pthread_rdlock_unlock() error");
    }
}

void info_handshake_from_connection(PeerConnection *peer) {
    if (peer == NULL) return;
    TorrentFile *torrent = peer->torrent;
    if (torrent == NULL) return;
    if (torrent->peers == NULL) if (!get_peers(torrent)) return;
    if (peer->idx >= torrent->num_peers) {
        ERROR("Peer index %zu out of range of %zu",
                peer->idx, torrent->num_peers);
        return;
    }
    char *host = torrent->peers[peer->idx].host;
    char *port = torrent->peers[peer->idx].port;
#define PEER_LOG(fmt, ...) ELOG("%s:%s (fd=%d): " fmt "\n", host, port, peer->fd, ##__VA_ARGS__);
    if (peer->fd == -1 || peer->fd == 0) {
        PEER_LOG("Connecting and handshaking");
        if (!get_handshake(peer)) {
            // FIXME handle retries
            ERROR("Failed to connect and handshake");
            return;
        }
    }

    if (pthread_mutex_lock(&print_lock) != 0) {
        perror("pthread_mutex_lock() error");
        goto close;
    }

    printf("Peer ID: ");
    for (int idx = 0; idx < PEER_ID_SIZE; idx ++) {
        printf("%02x", peer->peer_id[idx]);
    }
    printf("\n");

    if (pthread_mutex_unlock(&print_lock) != 0) {
        perror("pthread_mutex_lock() error");
    }
close:
    if (peer->fd > 0) {
        close(peer->fd);
        peer->fd = -1;
    }
}

void info_handshake(const char *data, size_t peer) {
    ELOG("(%s, %zu)\n", data, peer);
    if (data == NULL) return;
    TorrentFile *torrent = parse_torrent_file_or_magnet(data);
    if (torrent == NULL) return;
    if (!get_peers(torrent)) return;
    PeerConnection connection = {
        .idx = peer,
        .torrent = torrent,
    };
    info_handshake_from_connection(&connection);
}

void info_peers(const char *data) {
    ELOG("(%p)\n", data);
    if (data == NULL) return;
    TorrentFile *torrent = parse_torrent_file_or_magnet(data);
    if (torrent == NULL) return;
    if (!get_peers(torrent)) return;
    if (pthread_rwlock_rdlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_rdlock() error");
        return;
    }

    if (torrent->num_peers == 0 || torrent->peers == NULL) {
        ELOG("No peers\n");
        goto unlock_torrent;
    }

    if (pthread_mutex_lock(&print_lock) != 0) {
        perror("pthread_mutex_lock() error");
        goto unlock_torrent;
    }
    for (size_t idx = 0; idx < torrent->num_peers; idx ++) {
        printf("%s:%s\n", torrent->peers[idx].host, torrent->peers[idx].port);
    }

    if (pthread_mutex_unlock(&print_lock) != 0) {
        perror("pthread_mutex_unlock() error");
    }
unlock_torrent:
    if (pthread_rwlock_rdlock(&torrent->lock) != 0) {
        perror("pthread_rwlock_rdlock() error");
    }
}

#include "io.h"

// 2^14 (16 kiB)
#define BLOCK_SIZE 16384

#define EXPECT_PACKET_SIZE(fd, current_packet_length, size) \
    if ((current_packet_length) != (size)) { \
        ELOG("Unexpected payload size %d, expected %d. Ignoring packet\n", \
                (current_packet_length), (size)); \
        DRAIN((fd), (current_packet_length)); \
        break; \
    }

#include <arpa/inet.h>

typedef struct {
    uint32_t index;
    uint32_t begin;
    uint32_t length;
} RequestPayload;

void *handle_connection(void *data) {
    if (data == NULL) return NULL;
    PeerConnection *peer = (PeerConnection *)data;
    TorrentFile *torrent = peer->torrent;
    if (torrent->peers == NULL) if (!get_peers(torrent)) return NULL;
    if (peer->idx >= torrent->num_peers) {
        ERROR("Peer index %zu out of range of %zu",
                peer->idx, torrent->num_peers);
        return NULL;
    }
    char *host = torrent->peers[peer->idx].host;
    char *port = torrent->peers[peer->idx].port;
#define PEER_LOG(fmt, ...) ELOG("%s:%s (fd=%d): " fmt "\n", host, port, peer->fd, ##__VA_ARGS__);
    if (peer->fd == -1 || peer->fd == 0) {
        PEER_LOG("Connecting and handshaking");
        if (!get_handshake(peer)) {
            // FIXME handle retries
            ERROR("Failed to connect and handshake");
            return NULL;
        }
    }

    size_t requests = 0;
    bool complete = false;
    bool init = false;
    PEER_LOG("Handling connection");
    uint8_t bitfield = 0;
    while (!complete || !init) {
        if (init) PEER_LOG("Outstanding requests: %zu", requests);
        uint32_t packet_length = 0;
        if (!read_full(peer->fd, packet_length)) {
            PEER_LOG("Connection lost");
            peer->fd = -1;
            break;
        }
        packet_length = ntohl(packet_length);
        PEER_LOG("Received packet of length %u", packet_length);
        if (packet_length > 0) {
            PeerMessageType type = CHOKE;
            if (!read_full_length(peer->fd, &type, 1)) goto end;
            packet_length -= 1;
            static_assert(NUM_TYPES == 9, "BEP 003 Peer Message Types");
            switch (type) {
                case EXTENDED:
                    /* BEP 010 Extension Protocol */
                    (void) type;
                    uint8_t id;
                    if (!read_full(peer->fd, id)) break;
                    packet_length -= 1;
                    static_assert(NUM_EXTENSIONS == 2, "BEP 010 Handshake, BEP 009 Metadata, nil others");
                    if (id == 0) {
                        PEER_LOG("received EXTENDED handshake");
                        /* Handshake */
                        uint8_t *message = (uint8_t *)malloc(packet_length);
                        if (message == NULL) break;
                        if (!read_full_length(peer->fd, message, packet_length)) {
                            free(message);
                            break;
                        }
                        BencodedValue *decoded = decode_bencoded_bytes(message, message + packet_length);
                        if (!decoded) {
                            free(message);
                            break;
                        }
                        if (decoded->type != DICT) {
                            free(message);
                            break;
                        }
                        BencodedDict *dict = (BencodedDict *)decoded->data;
                        BencodedValue *m = bencoded_dict_value(dict, "m");

                        /* FIXME store in peer connection? */
                        free(message);
                    } else {
                        PEER_LOG("received EXTENDED id %d", id);

                        UNIMPLEMENTED("Lookup EXTENDED dict");
                    }

                    /* UNIMPLEMENTED("EXTENDED"); */
                    break;

                case CHOKE:
                    PEER_LOG("received CHOKE");
                    peer->unchoked = false;
                    break;

                case UNCHOKE:
                    PEER_LOG("received UNCHOKE");
                    EXPECT_PACKET_SIZE(peer->fd, packet_length, 0);
                    peer->unchoked = true;
                    if (!peer->interested) {
                        PEER_LOG("Unexpected state, peer is not set to INTERESTED. Ignoring packet");
                        break;
                    }

                    type = REQUEST;
                    packet_length = htonl(sizeof(RequestPayload) + 1);

                    /* FIXME The bittorrent paper (http://bittorrent.org/bittorrentecon.pdf S2.3) suggests 5 requests at a time */
                    /* FIXME how many do we have currently if we had been choked then unchoked */
                    for (size_t idx = 0; idx < 5; idx ++) {
                        /* FIXME Check whether it has available pieces (in bitfield) */
                        RequestPayload *payload = (RequestPayload *)queue_pop(&torrent->requests);
                        if (payload == NULL) break;
                        requests ++;
                        PEER_LOG("sent REQUEST(%d, %d, %d)", ntohl(payload->index), ntohl(payload->begin), ntohl(payload->length));
                        if (!write_full(peer->fd, packet_length)) break;
                        if (!write_full_length(peer->fd, &type, 1)) break;
                        if (!write_full(peer->fd, *payload)) break;
                    }

                    if (requests == 0) complete = true;

                    break;

                case INTERESTED:
                    PEER_LOG("received INTERESTED");
                    peer->interested = true;

                    /* FIXME can we send them something? Should we unchoke our end? */

                    UNIMPLEMENTED("INTERESTED");
                    break;

                case NOT_INTERESTED:
                    PEER_LOG("received NOT_INTERESTED");
                    peer->interested = false;

                    /* FIXME Should we now choke our end? */

                    UNIMPLEMENTED("NOT_INTERESTED");
                    break;

                case HAVE:
                    UNIMPLEMENTED("HAVE");
                    break;

                case BITFIELD:
                    EXPECT_PACKET_SIZE(peer->fd, packet_length, 1);
                    if (bitfield != 0) {
                        PEER_LOG("Unexpected state, BITFIELD has already been set. Ignoring packet");
                        break;
                    }

                    if (!read_full(peer->fd, bitfield)) break;
                    PEER_LOG("received BITFIELD(%x)", bitfield);
                    /* FIXME Check whether it has available pieces */

                    /* FIXME check whether we even need to be interested */
                    /*       Maybe at this point we can read from torrent workqueue (and maybe block until needed) */
                    packet_length = htonl(1);
                    type = INTERESTED;
                    if (!write_full(peer->fd, packet_length)) break;
                    if (!write_full_length(peer->fd, &type, 1)) break;
                    PEER_LOG("sent INTERESTED");
                    peer->interested = true;

                    init = true;

                    break;

                case REQUEST:
                    UNIMPLEMENTED("REQUEST");
                    break;

                case PIECE:
                    if (!peer->unchoked || !peer->interested) {
                        // The spec says this could happen if a choke/unchoke message pair sent quickly, or if download is slow
                        // FIXME should this add back to queue?
                        ERROR("Bad state. Unexpected PIECE message");
                        DRAIN(peer->fd, packet_length);
                        break;
                    }

                    if (packet_length < sizeof(uint32_t) * 2) {
                        ERROR("Expected uint32_t index and uint32_t begin, but only %u bytes in packet",
                                packet_length);

                        DRAIN(peer->fd, packet_length);
                        break;
                    }
                    uint32_t piece, begin;
                    if (!read_full(peer->fd, piece)) break;
                    if (!read_full(peer->fd, begin)) break;
                    piece = ntohl(piece);
                    begin = ntohl(begin);
                    packet_length -= sizeof(uint32_t) * 2;
                    PEER_LOG("received PIECE(%u, %u, %u)", piece, begin, packet_length);

                    if (piece >= torrent->num_pieces) {
                        ERROR("Invalid piece number. Out of range.");
                        DRAIN(peer->fd, packet_length);
                        break;
                    }

                    /* FIXME validate we were expecting this request? */
                    if (!read_full_length(peer->fd, torrent->data + piece * torrent->piece_length + begin, packet_length)) {
                        ERROR("Could not read PIECE.");
                        break;
                    }

                    requests --;

                    /* FIXME The bittorrent paper (http://bittorrent.org/bittorrentecon.pdf S2.3) suggests 5 requests at a time */
                    /* FIXME The bittorrent paper (http://bittorrent.org/bittorrentecon.pdf S2.4) describes alternative algorithms, such as end-game */
                    /*       For now, just grab another and send it */

                    while (requests < 5) {
                        RequestPayload *payload = (RequestPayload *)queue_pop(&torrent->requests);
                        if (payload == NULL) break;
                        PEER_LOG("sent REQUEST(%d, %d, %d)", ntohl(payload->index), ntohl(payload->begin), ntohl(payload->length));
                        requests ++;
                        if (!write_full(peer->fd, packet_length)) break;
                        if (!write_full_length(peer->fd, &type, 1)) break;
                        if (!write_full(peer->fd, *payload)) break;
                    }
                    if (requests == 0) {
                        PEER_LOG("No more outstanding requests");
                        complete = true;
                    } else {
                        PEER_LOG("Still have %zu requests outstanding", requests);
                    }

                    break;

                case CANCEL:
                    UNIMPLEMENTED("CANCEL");
                    break;

                default:
                    WARNING("Received undefined peer message type %d", type);
                    DRAIN(peer->fd, packet_length);
                    goto end;
            }
        }
    }

end:

    return NULL;
}

void download_torrent_from_input(const char *data) {
    ELOG("(%p)\n", data);
    FILE *out = NULL;
    pthread_t *threads = NULL;
    PeerConnection *peers = NULL;
    RequestPayload *requests = NULL;
    if (data == NULL) return;
    
    TorrentFile *torrent = parse_torrent_file_or_magnet(data);
    if (torrent == NULL) return;

    if (!get_peers(torrent)) goto end;
    // FIXME torrent->length is not known if magnet until after extension handshake
    //          perhaps if magnet route we should grab a random peer and handshake?

    ELOG("torrent length %zu\n", torrent->length);
    ELOG("torrent piece_length %zu\n", torrent->piece_length);
    torrent->data = malloc(torrent->length);
    if (torrent->data == NULL) goto end;

    peers = calloc(torrent->num_peers, sizeof(PeerConnection));
    if (peers == NULL) goto end;
    threads = calloc(torrent->num_peers, sizeof(pthread_t));
    if (threads == NULL) goto end;
    requests = calloc(torrent->num_peers * torrent->num_pieces, sizeof(RequestPayload));
    if (requests == NULL) goto end;

    for (size_t idx = 0; idx < torrent->num_peers; idx ++) {
        PeerConnection *peer = &peers[idx];
        if (peer == NULL) continue;
        peer->torrent = torrent;
        peer->idx = idx;
        pthread_create(&threads[idx], NULL, handle_connection, peer);
    }

    /* FIXME Some better peer selection algorithms described in the bittorrent paper
     *       (http://bittorrent.org/bittorrentecon.pdf S2.4)
     *       suggests random first to start
     *       then rarest first for main
     *       then endgame mode to finish
     *       for now, just do it sequencially
     */
    for (size_t piece = 0; piece < torrent->num_pieces; piece ++) {
        uint32_t len = piece + 1 < torrent->num_pieces ?
            torrent->piece_length :
            torrent->length - (torrent->num_pieces - 1) * torrent->piece_length;

        size_t end = len / BLOCK_SIZE;
        for (size_t idx = 0; idx < end; idx ++) {
            RequestPayload *request = &requests[piece * torrent->num_pieces + idx];
            request->index = htonl(piece);
            request->begin = htonl(idx * BLOCK_SIZE);
            request->length = htonl(BLOCK_SIZE);
            ELOG("Queuing REQUEST(%zu, %zu, %d)\n", piece, idx * BLOCK_SIZE, BLOCK_SIZE);
            queue_push(&torrent->requests, request);
        }
        if (end * BLOCK_SIZE != len) {
            RequestPayload *request = &requests[(piece + 1) * torrent->num_pieces - 1];
            request->index = htonl(piece);
            request->begin = htonl(end * BLOCK_SIZE);
            request->length = htonl(len % BLOCK_SIZE);
            ELOG("Queuing REQUEST(%zu, %zu, %d)\n", piece, end * BLOCK_SIZE, len % BLOCK_SIZE);
            queue_push(&torrent->requests, request);
        }
    }

    // FIXME wait until torrent->requests is empty
    //       probably need another queue to track outstanding rather than just counter
    //       then wait until *both* are empty
    // There is now a cond and a lock in torrent->pieces[idx].lock, and .complete

    for (size_t idx = 0; idx < torrent->num_peers; idx ++) {
        pthread_join(threads[idx], NULL); // Is there a group join?
    }

    for (size_t piece = 0; piece < torrent->num_pieces; ++piece) {
        uint8_t *data = torrent->data + (piece * torrent->piece_length);
        size_t len = torrent->piece_length;
        if ((unsigned)piece + 1 == torrent->num_pieces) {
            len = torrent->length - (torrent->num_pieces - 1) * torrent->piece_length;
        }
        // FIXME check hash
        uint8_t piece_hash[SHA1_DIGEST_BYTE_LENGTH];
        if (!sha1_digest(data, len, piece_hash)) {
            goto end;
        }

        if (memcmp(piece_hash, torrent->pieces[piece].hash, SHA1_DIGEST_BYTE_LENGTH) != 0) {
            fprintf(stderr, "Piece hash mixmatch for piece %ld\n", piece);
            fprintf(stderr, "Expected: ");
            for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
                fprintf(stderr, "%02x", torrent->pieces[piece].hash[idx]);
            }
            fprintf(stderr, "\n");
            fprintf(stderr, "Actual:   ");
            for (int idx = 0; idx < SHA1_DIGEST_BYTE_LENGTH; idx ++) {
                fprintf(stderr, "%02x", piece_hash[idx]);
            }
            fprintf(stderr, "\n");
            goto end;
        }
    }

    out = fopen(torrent->name, "w");
    if (out == NULL) {
        ERROR("Could not open output file");
        goto end;
    }
    int out_fd = fileno(out);
    if (!write_full_length(out_fd, torrent->data, torrent->length)) {
        ERROR("Could not write output file");
        goto end;
    }

    ELOG("Success\n");

end:
    ELOG("returning\n");
    if (torrent) {
        free(torrent->tracker);
        free(torrent->name);
        free(torrent->data);
        free(torrent);
    }
    if (peers) free(peers);
    if (threads) free(threads);
    if (requests) free(requests);
    if (out) fclose(out);
}

int job_test() {
    pthread_mutex_init(&print_lock, NULL);

    JobList jobs = {0};
    job_list_init(&jobs);

    info_peers("sample.torrent");
    info_handshake("sample.torrent", 0);
    info_handshake("sample.torrent", 1);
    info_handshake("sample.torrent", 2);
    info_torrent_file("sample.torrent");
    download_torrent_from_input("sample.torrent");
    /* download_torrent_from_input("magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce"); */

    job_list_free(&jobs);

    return 70;
}
