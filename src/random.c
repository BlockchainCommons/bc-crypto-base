//
//  random.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include <assert.h>
#include <string.h>

#include "random.h"
#include "randombytes.h"
#include "mersenne-twister.h"
#include "sha2.h"
#include "hkdf.h"

void crypto_random(uint8_t* buf, size_t n) {
    assert(randombytes(buf, n) == 0);
}

void seed_mersenne_twister(uint32_t s) {
    seed(s);
}

void seed_mersenne_twister_string(const char* string) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw((uint8_t*)string, strlen(string), digest);
    seed_mersenne_twister(*(uint32_t*)digest);
}

void mersenne_twister_random(uint8_t* buf, size_t n) {
    size_t words = n / sizeof(uint32_t);
    size_t bytes = n % sizeof(uint32_t);
    uint8_t* p = buf;
    for(int i = 0; i < words; i++) {
        *(uint32_t*)p = rand_u32();
        p += sizeof(uint32_t);
    }
    if (bytes > 0) {
        uint32_t a = rand_u32();
        uint8_t* q = (uint8_t*)&a;
        for(int i = 0; i < bytes; i++) {
            *p++ = *q++;
        }
    }
}

static uint8_t deterministic_seed[SHA256_DIGEST_LENGTH];
static uint64_t deterministic_salt = 0;

void seed_deterministic_string(const char* string) {
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Raw((uint8_t*)string, strlen(string), deterministic_seed);
    deterministic_salt = 0;
}

void deterministic_random(uint8_t* buf, size_t n) {
    deterministic_salt += 1;
    hkdf_sha256(buf, n,
    (uint8_t*)&deterministic_salt, sizeof(deterministic_salt),
    deterministic_seed, SHA256_DIGEST_LENGTH,
    NULL, 0);
}
