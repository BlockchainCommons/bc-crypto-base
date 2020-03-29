//
//  test.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

// Arduino has two problems with the tests:
// 1. The test-utils are duplicated w/ other Blockchain Commons packages.
// 2. The main routine conflicts w/ the actual main.
#if !defined(ARDUINO)

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "bc-crypto-base.h"
#include "test-utils.h"

bool _test_sha(const char* input, const char* expected_output, size_t digest_length, void (*f)(const uint8_t*, size_t, uint8_t*)) {
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
void test_sha() {
  char* input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  assert(_test_sha(input, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", SHA1_DIGEST_LENGTH, sha1_Raw));
  assert(_test_sha(input, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", SHA256_DIGEST_LENGTH, sha256_Raw));
  assert(_test_sha(input, "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445", SHA512_DIGEST_LENGTH, sha512_Raw));
}

bool _test_hmac(const uint8_t* key_data, size_t key_len, const uint8_t* message_data, size_t message_len, const char* expected_output, size_t digest_length, void (*f)(const uint8_t*, const uint32_t, const uint8_t*, const uint32_t, uint8_t*)) {
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

void _test_hmac_2(const uint8_t* key_data, size_t key_len, const uint8_t* message_data, size_t message_len, const char* expected_output_256, const char* expected_output_512) {
  assert(_test_hmac(key_data, key_len, message_data, message_len, expected_output_256, SHA256_DIGEST_LENGTH, hmac_sha256));
  assert(_test_hmac(key_data, key_len, message_data, message_len, expected_output_512, SHA512_DIGEST_LENGTH, hmac_sha512));
}

void _test_hmac_hex_string(const char* key, const char* message, const char* expected_output_256, const char* expected_output_512) {
  uint8_t* key_data;
  size_t key_len = hex_to_data(key, &key_data);

  uint8_t* message_data = (uint8_t*)message;
  size_t message_len = strlen(message);

  _test_hmac_2(key_data, key_len, message_data, message_len, expected_output_256, expected_output_512);

  free(key_data);
}

void _test_hmac_string_string(const char* key, const char* message, const char* expected_output_256, const char* expected_output_512) {
  uint8_t* key_data = (uint8_t*)key;
  size_t key_len = strlen(key);

  uint8_t* message_data = (uint8_t*)message;
  size_t message_len = strlen(message);

  _test_hmac_2(key_data, key_len, message_data, message_len, expected_output_256, expected_output_512);
}

void _test_hmac_hex_hex(const char* key, const char* message, const char* expected_output_256, const char* expected_output_512) {
  uint8_t* key_data;
  size_t key_len = hex_to_data(key, &key_data);

  uint8_t* message_data;
  size_t message_len = hex_to_data(message, &message_data);

  _test_hmac_2(key_data, key_len, message_data, message_len, expected_output_256, expected_output_512);

  free(key_data);
  free(message_data);
}

// Test vectors: https://tools.ietf.org/html/rfc4231
void test_hmac() {
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

void _test_pbkdf2_data(const uint8_t* password_data, size_t password_len, const uint8_t* salt_data, size_t salt_len, uint32_t iterations, size_t key_len, const char* expected_key) {
  uint8_t* key_data = malloc(key_len);
  pbkdf2_hmac_sha256(password_data, password_len, salt_data, salt_len, iterations, key_data, key_len);
  char* key = data_to_hex(key_data, key_len);
  assert(equal_strings(key, expected_key));
  free(key);
}

void _test_pbkdf2(const char* password, const char* salt, uint32_t iterations, size_t key_len, const char* expected_key) {
  uint8_t* password_data = (uint8_t*)password;
  size_t password_len = strlen(password);
  uint8_t* salt_data = (uint8_t*)salt;
  size_t salt_len = strlen(salt);
  _test_pbkdf2_data(password_data, password_len, salt_data, salt_len, iterations, key_len, expected_key);
}

// Test vectors: https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
void test_pbkdf2() {
  _test_pbkdf2("password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  _test_pbkdf2("password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  _test_pbkdf2("password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  // This one takes a long time.
  // _test_pbkdf2("password", "salt", 16777216, 32, "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46");
  _test_pbkdf2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40, "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
  _test_pbkdf2_data((uint8_t*)"pass\0word", 9, (uint8_t*)"sa\0lt", 5, 4096, 16, "89b69d0516f829893c696226650a8687");
}

int main() {
  test_hex();
  test_sha();
  test_hmac();
  test_pbkdf2();
}

#endif // !defined(ARDUINO)
