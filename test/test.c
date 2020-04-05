//
//  test.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "../src/bc-crypto-base.h"
#include "test-utils.h"

static bool _test_sha(const char* input, const char* expected_output, size_t digest_length, void (*f)(const uint8_t*, size_t, uint8_t*)) {
  bool pass = false;
  uint8_t output[digest_length];
  f((uint8_t *)input, strlen(input), output);
  char* out_string = data_to_hex(output, digest_length);
  if(equal_strings(out_string, expected_output)) {
    pass = true;
  }
  free(out_string);
  return pass;
}

// Test vectors: https://www.di-mgt.com.au/sha_testvectors.html
static void test_sha() {
  char* input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  assert(_test_sha(input, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", SHA1_DIGEST_LENGTH, sha1_Raw));
  assert(_test_sha(input, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", SHA256_DIGEST_LENGTH, sha256_Raw));
  assert(_test_sha(input, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445", SHA512_DIGEST_LENGTH, sha512_Raw));
}

static bool _test_hmac(const uint8_t* key_data, size_t key_len, const uint8_t* message_data, size_t message_len, const char* expected_output, size_t digest_length, void (*f)(const uint8_t*, const uint32_t, const uint8_t*, const uint32_t, uint8_t*)) {
  bool pass = false;

  uint8_t output[digest_length];
  f(key_data, key_len, message_data, message_len, output);
  char* out_string = data_to_hex(output, digest_length);
  if(equal_strings(out_string, expected_output)) {
    pass = true;
  }

  free(out_string);

  return pass;
}

static void _test_hmac_2(const uint8_t* key_data, size_t key_len, const uint8_t* message_data, size_t message_len, const char* expected_output_256, const char* expected_output_512) {
  assert(_test_hmac(key_data, key_len, message_data, message_len, expected_output_256, SHA256_DIGEST_LENGTH, hmac_sha256));
  assert(_test_hmac(key_data, key_len, message_data, message_len, expected_output_512, SHA512_DIGEST_LENGTH, hmac_sha512));
}

static void _test_hmac_hex_string(const char* key, const char* message, const char* expected_output_256, const char* expected_output_512) {
  uint8_t* key_data;
  size_t key_len = hex_to_data(key, &key_data);

  uint8_t* message_data = (uint8_t*)message;
  size_t message_len = strlen(message);

  _test_hmac_2(key_data, key_len, message_data, message_len, expected_output_256, expected_output_512);

  free(key_data);
}

static void _test_hmac_string_string(const char* key, const char* message, const char* expected_output_256, const char* expected_output_512) {
  uint8_t* key_data = (uint8_t*)key;
  size_t key_len = strlen(key);

  uint8_t* message_data = (uint8_t*)message;
  size_t message_len = strlen(message);

  _test_hmac_2(key_data, key_len, message_data, message_len, expected_output_256, expected_output_512);
}

static void _test_hmac_hex_hex(const char* key, const char* message, const char* expected_output_256, const char* expected_output_512) {
  uint8_t* key_data;
  size_t key_len = hex_to_data(key, &key_data);

  uint8_t* message_data;
  size_t message_len = hex_to_data(message, &message_data);

  _test_hmac_2(key_data, key_len, message_data, message_len, expected_output_256, expected_output_512);

  free(key_data);
  free(message_data);
}

// Test vectors: https://tools.ietf.org/html/rfc4231
static void test_hmac() {
  _test_hmac_hex_string(
    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "Hi There",
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
  );

  _test_hmac_string_string(
    "Jefe",
    "what do ya want for nothing?",
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
  );

  _test_hmac_hex_hex(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
  );

  _test_hmac_hex_hex(
    "0102030405060708090a0b0c0d0e0f10111213141516171819",
    "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
  );

  _test_hmac_hex_string(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "Test Using Larger Than Block-Size Key - Hash Key First",
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
  );

  _test_hmac_hex_string(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
  );
}

static void _test_pbkdf2_data(const uint8_t* password_data, size_t password_len, const uint8_t* salt_data, size_t salt_len, uint32_t iterations, size_t key_len, const char* expected_key) {
  uint8_t* key_data = malloc(key_len);
  pbkdf2_hmac_sha256(password_data, password_len, salt_data, salt_len, iterations, key_data, key_len);
  char* key = data_to_hex(key_data, key_len);
  assert(equal_strings(key, expected_key));
  free(key);
}

static void _test_pbkdf2(const char* password, const char* salt, uint32_t iterations, size_t key_len, const char* expected_key) {
  uint8_t* password_data = (uint8_t*)password;
  size_t password_len = strlen(password);
  uint8_t* salt_data = (uint8_t*)salt;
  size_t salt_len = strlen(salt);
  _test_pbkdf2_data(password_data, password_len, salt_data, salt_len, iterations, key_len, expected_key);
}

// Test vectors: https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
static void test_pbkdf2() {
  _test_pbkdf2("password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  _test_pbkdf2("password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  _test_pbkdf2("password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  // This one takes a long time.
  // _test_pbkdf2("password", "salt", 16777216, 32, "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46");
  _test_pbkdf2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
  _test_pbkdf2_data((uint8_t*)"pass\0word", 9, (uint8_t*)"sa\0lt", 5, 4096, 16, "89b69d0516f829893c696226650a8687");
}

static bool _test_hkdf(const char* ikm, const char* salt, const char* info, const char* okm) {
    uint8_t* ikm_data;
    size_t ikm_len = hex_to_data(ikm, &ikm_data);

    uint8_t* salt_data;
    size_t salt_len = hex_to_data(salt, &salt_data);

    uint8_t* info_data;
    size_t info_len = hex_to_data(info, &info_data);

    uint8_t* expected_okm_data;
    size_t okm_len = hex_to_data(okm, &expected_okm_data);

    uint8_t* okm_data = calloc(okm_len, sizeof(uint8_t));

    hkdf_sha256(okm_data, okm_len,
        salt_data, salt_len,
        ikm_data, ikm_len,
        info_data, info_len
    );

    bool result = equal_uint8_buffers(okm_data, okm_len, expected_okm_data, okm_len);

    free(ikm_data);
    free(salt_data);
    free(info_data);
    free(expected_okm_data);

    return result;
}

// Test vectors from:
// https://github.com/rustyrussell/ccan/blob/master/ccan/crypto/hkdf_sha256/test/api-rfc5869.c
static void test_hkdf() {
    char* ikm1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    char* salt1 = "000102030405060708090a0b0c";
    char* info1 = "f0f1f2f3f4f5f6f7f8f9";
    char* okm1 = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    assert(_test_hkdf(ikm1, salt1, info1, okm1));

    char* ikm2 =
    "000102030405060708090a0b0c0d0e0f"
	"101112131415161718191a1b1c1d1e1f"
	"202122232425262728292a2b2c2d2e2f"
	"303132333435363738393a3b3c3d3e3f"
	"404142434445464748494a4b4c4d4e4f";
    char* salt2 =
    "606162636465666768696a6b6c6d6e6f"
	"707172737475767778797a7b7c7d7e7f"
	"808182838485868788898a8b8c8d8e8f"
	"909192939495969798999a9b9c9d9e9f"
	"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
    char* info2 =
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
	"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
	"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
	"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    char* okm2 =
    "b11e398dc80327a1c8e7f78c596a4934"
	"4f012eda2d4efad8a050cc4c19afa97c"
	"59045a99cac7827271cb41c65e590e09"
	"da3275600c2f09b8367793a9aca3db71"
	"cc30c58179ec3e87c14c01d5c1f3434f"
	"1d87";
    assert(_test_hkdf(ikm2, salt2, info2, okm2));

    char* ikm3 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    char* salt3 = "";
    char* info3 = "";
    char* okm3 = 
    "8da4e775a563c18f715f802a063c5a31"
	"b8a11f5c5ee1879ec3454e5f3c738d2d"
	"9d201395faa4b61a96c8";
    assert(_test_hkdf(ikm3, salt3, info3, okm3));
}

void _test_rng(void (*rng)(uint8_t*, size_t), void (*seeder)(const char*), uint8_t* digest) {
    size_t buf_len = 100;
    size_t iterations = 1000;
    uint8_t buf1[buf_len];
    uint8_t buf2[buf_len];

    if (seeder != NULL) {
        seeder("test");
    }

    rng(buf1, buf_len);

    SHA256_CTX ctx;
    sha256_Init(&ctx);
    for(int i = 0; i < iterations; i++) {
        sha256_Update(&ctx, buf1, buf_len);
        memcpy(buf2, buf1, buf_len);
        rng(buf1, buf_len);
        assert(memcmp(buf1, buf2, buf_len) != 0);
    }
    uint8_t d[SHA256_DIGEST_LENGTH];
    sha256_Final(&ctx, d);

    if (digest != NULL) {
        memcpy(digest, d, SHA256_DIGEST_LENGTH);
    }
}

void _test_deterministic_rng(void (*rng)(uint8_t*, size_t), void (*seeder)(const char*)) {
    uint8_t digest1[SHA256_DIGEST_LENGTH];
    _test_rng(rng, seeder, digest1);
    uint8_t digest2[SHA256_DIGEST_LENGTH];
    _test_rng(rng, seeder, digest2);
    assert(memcmp(digest1, digest2, SHA256_DIGEST_LENGTH) == 0);
}

void test_random() {
    _test_rng(crypto_random, NULL, NULL);
    _test_deterministic_rng(mersenne_twister_random, seed_mersenne_twister_string);
    _test_deterministic_rng(deterministic_random, seed_deterministic_string);
}

int main() {
  test_hex();
  test_sha();
  test_hmac();
  test_pbkdf2();
  test_hkdf();
  test_random();
}
