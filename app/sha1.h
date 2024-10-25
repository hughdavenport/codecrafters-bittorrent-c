#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>

#define SHA1_DIGEST_BYTE_LENGTH 20

bool sha1_digest(const uint8_t *data,
                size_t length,
                uint8_t result[SHA1_DIGEST_BYTE_LENGTH]);

#endif // SHA1_H

#ifdef SHA1_IMPLEMENTATION

#define _SHA1_MAX_LENGTH 18446744073709551614UL // 2^64 - 1
#define _SHA1_BLOCK_SIZE 64
#define _BYTE_MASK 0xFF

#define SHA1_S(n, X) (((X) << (n)) | ((X) >> (32-(n))))

void _sha1_process_block(uint8_t M[_SHA1_BLOCK_SIZE], uint32_t H[5]) {
    // This function is implementing Method 1 of RFC 3174.

    // Names from RFC 3174
    //          M is 512 bit block (parameter)
    //          A-E is a 5 word buffer
    //          H is a 5 word buffer (parameter is last block's H or IVs)
    //          W is a 80 word sequence
    //          TEMP is a buffer
    uint32_t A, B, C, D, E;
    uint32_t W[80];
    uint32_t TEMP;

    // Step a.
    for (int t = 0; t < 16; t ++) {
        W[t] = ((((uint32_t)M[t*4]) & _BYTE_MASK) << 24) |
            ((((uint32_t)M[t*4 + 1]) & _BYTE_MASK) << 16) |
            ((((uint32_t)M[t*4 + 2]) & _BYTE_MASK) << 8) |
            (((uint32_t)M[t*4 + 3]) & _BYTE_MASK);
    }

    // Step b.
    for (int t = 16; t < 80; t ++) {
        W[t] = SHA1_S(1,
                W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
        );
    }

    // Step c.
    A = H[0];
    B = H[1];
    C = H[2];
    D = H[3];
    E = H[4];

    // Step d.
    const uint32_t K[5] = {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    for (int t = 0; t < 20; t ++) {
        TEMP = SHA1_S(5, A) +
            ((B & C) | ((~B) & D)) + // f(t;B,C,D)
            E + W[t] + K[0];
        E = D; D = C; C = SHA1_S(30, B);
        B = A; A = TEMP;
    }
    for (int t = 20; t < 40; t ++) {
        TEMP = SHA1_S(5, A) +
            (B ^ C ^ D) + // f(t;B,C,D)
            E + W[t] + K[1];
        E = D; D = C; C = SHA1_S(30, B);
        B = A; A = TEMP;
    }
    for (int t = 40; t < 60; t ++) {
        TEMP = SHA1_S(5, A) +
            ((B & C) | (B & D) | (C & D)) + // f(t;B,C,D)
            E + W[t] + K[2];
        E = D; D = C; C = SHA1_S(30, B);
        B = A; A = TEMP;
    }
    for (int t = 60; t < 80; t ++) {
        TEMP = SHA1_S(5, A) +
            (B ^ C ^ D) + // f(t;B,C,D)
            E + W[t] + K[3];
        E = D; D = C; C = SHA1_S(30, B);
        B = A; A = TEMP;
    }

    // Step e.
    H[0] += A;
    H[1] += B;
    H[2] += C;
    H[3] += D;
    H[4] += E;
}

void _sha1_pad_block(uint8_t M[_SHA1_BLOCK_SIZE], uint32_t H[5], uint64_t length) {
    int idx = length % _SHA1_BLOCK_SIZE;
    length *= 8;
    M[idx++] = 0x80;
    if (idx >= (_SHA1_BLOCK_SIZE) - 2) {
        fprintf(stderr, "%s:%d: pad block over two blocks\n", __FILE__, __LINE__);
        while (idx < _SHA1_BLOCK_SIZE) {
            M[idx++] = 0;
        }
        _sha1_process_block(M, H);
        idx = 0;
    }
    while (idx < (_SHA1_BLOCK_SIZE - 2)) {
        M[idx++] = 0;
    }
    M[_SHA1_BLOCK_SIZE - 2] = (length >> 32) & 0xFF;
    M[_SHA1_BLOCK_SIZE - 1] = length & 0xFF;
}

bool sha1_digest(const uint8_t *data,
                uint64_t length,
                uint8_t result[SHA1_DIGEST_BYTE_LENGTH]) {

    if (length > _SHA1_MAX_LENGTH) return false;

    // Name and initialisation values from RFC 3174
    uint32_t H[5];
    H[0] = 0x67452301;
    H[1] = 0xEFCDAB89;
    H[2] = 0x98BADCFE;
    H[3] = 0x10325476;
    H[4] = 0xC3D2E1F0;

    uint8_t block[_SHA1_BLOCK_SIZE];
    for (size_t idx = 0; idx < length; ) {
        block[idx % _SHA1_BLOCK_SIZE] = data[idx];
        if ((++idx) % _SHA1_BLOCK_SIZE == 0) {
            _sha1_process_block(block, H);
        }
    }

    if (length % _SHA1_BLOCK_SIZE != 0) {
        _sha1_pad_block(block, H, length);
        _sha1_process_block(block, H);
    }

//  After processing M(n), the message digest is the 160-bit string
//     represented by the 5 words
//              H0 H1 H2 H3 H4
//

    result[0] = H[0];
    result[1] = H[1];
    result[2] = H[2];
    result[3] = H[3];
    result[4] = H[4];

    return true;
}

#endif // SHA1_IMPLEMENTATION
