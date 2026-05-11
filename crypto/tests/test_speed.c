#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "bip32.h"
#include "curves.h"
#include "ecdsa.h"
#include "ed25519-donna/ed25519.h"
#include "hasher.h"
#include "nist256p1.h"
#include "secp256k1.h"
#include "shrincs/shrincs.h"

static uint8_t msg[256];

void prepare_msg(void) {
  for (size_t i = 0; i < sizeof(msg); i++) {
    msg[i] = i * 1103515245;
  }
}

void bench_sign_secp256k1(int iterations) {
  uint8_t sig[64], priv[32], pby;

  const ecdsa_curve *curve = &secp256k1;

  memcpy(priv,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);

  for (int i = 0; i < iterations; i++) {
    ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);
  }
}

void bench_sign_nist256p1(int iterations) {
  uint8_t sig[64], priv[32], pby;

  const ecdsa_curve *curve = &nist256p1;

  memcpy(priv,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);

  for (int i = 0; i < iterations; i++) {
    ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);
  }
}

void bench_sign_ed25519(int iterations) {
  ed25519_secret_key sk;
  ed25519_signature sig;

  memcpy(sk,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);

  for (int i = 0; i < iterations; i++) {
    ed25519_sign(msg, sizeof(msg), sk, sig);
  }
}

void bench_verify_secp256k1_33(int iterations) {
  uint8_t sig[64], pub[33], priv[32], pby;

  const ecdsa_curve *curve = &secp256k1;

  memcpy(priv,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);
  ecdsa_get_public_key33(curve, priv, pub);
  ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);

  for (int i = 0; i < iterations; i++) {
    ecdsa_verify(curve, HASHER_SHA2, pub, sig, msg, sizeof(msg));
  }
}

void bench_verify_secp256k1_65(int iterations) {
  uint8_t sig[64], pub[65], priv[32], pby;

  const ecdsa_curve *curve = &secp256k1;

  memcpy(priv,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);
  ecdsa_get_public_key65(curve, priv, pub);
  ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);

  for (int i = 0; i < iterations; i++) {
    ecdsa_verify(curve, HASHER_SHA2, pub, sig, msg, sizeof(msg));
  }
}

void bench_verify_nist256p1_33(int iterations) {
  uint8_t sig[64], pub[33], priv[32], pby;

  const ecdsa_curve *curve = &nist256p1;

  memcpy(priv,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);
  ecdsa_get_public_key33(curve, priv, pub);
  ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);

  for (int i = 0; i < iterations; i++) {
    ecdsa_verify(curve, HASHER_SHA2, pub, sig, msg, sizeof(msg));
  }
}

void bench_verify_nist256p1_65(int iterations) {
  uint8_t sig[64], pub[65], priv[32], pby;

  const ecdsa_curve *curve = &nist256p1;

  memcpy(priv,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);
  ecdsa_get_public_key65(curve, priv, pub);
  ecdsa_sign(curve, HASHER_SHA2, priv, msg, sizeof(msg), sig, &pby, NULL);

  for (int i = 0; i < iterations; i++) {
    ecdsa_verify(curve, HASHER_SHA2, pub, sig, msg, sizeof(msg));
  }
}

void bench_verify_ed25519(int iterations) {
  ed25519_public_key pk;
  ed25519_secret_key sk;
  ed25519_signature sig;

  memcpy(sk,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);
  ed25519_publickey(sk, pk);
  ed25519_sign(msg, sizeof(msg), sk, sig);

  for (int i = 0; i < iterations; i++) {
    ed25519_sign_open(msg, sizeof(msg), pk, sig);
  }
}

void bench_multiply_curve25519(int iterations) {
  uint8_t result[32];
  uint8_t secret[32];
  uint8_t basepoint[32];

  memcpy(secret,
         "\xc5\x5e\xce\x85\x8b\x0d\xdd\x52\x63\xf9\x68\x10\xfe\x14\x43\x7c\xd3"
         "\xb5\xe1\xfb\xd7\xc6\xa2\xec\x1e\x03\x1f\x05\xe8\x6d\x8b\xd5",
         32);
  memcpy(basepoint,
         "\x96\x47\xda\xbe\x1e\xea\xaf\x25\x47\x1e\x68\x0b\x4d\x7c\x6f\xd1\x14"
         "\x38\x76\xbb\x77\x59\xd8\x3d\x0f\xf7\xa2\x49\x08\xfd\xda\xbc",
         32);

  for (int i = 0; i < iterations; i++) {
    curve25519_scalarmult(result, secret, basepoint);
  }
}

static HDNode root;

void prepare_node(void) {
  hdnode_from_seed((uint8_t *)"NothingToSeeHere", 16, SECP256K1_NAME, &root);
  hdnode_fill_public_key(&root);
}

void bench_ckd(int iterations) {
  char addr[MAX_ADDR_SIZE];
  HDNode node;
  for (int i = 0; i < iterations; i++) {
    memcpy(&node, &root, sizeof(HDNode));
    hdnode_public_ckd(&node, i);
    hdnode_fill_public_key(&node);
    ecdsa_get_address(node.public_key, HASHER_SHA2, HASHER_SHA2D, 0, addr,
                      sizeof(addr));
  }
}

uint8_t sl_signature[SL_SIZE];

void bench_sign_shrincs_stateless(int iterations) {
  SecretKey sk;
  PublicKey pk;

  memcpy(pk.seed,
         "\xa8\xe2\x87\xad\xc1\x50\x1e\xa8\x48\xd9\xe2\x9f\xce\x04\x46\x96",
         N);

  memcpy(pk.root,
         "\x2a\x39\x8e\xeb\x0b\x9f\x7a\xe6\x3d\x80\x0c\xfc\x44\x26\x92\x16",
         N);

  sk.pk = pk;

  memcpy(sk.sf,
         "\x4f\xaf\xef\xab\xe5\x2a\x69\x01\xd3\x37\x89\x1c\xff\x82\xc1\xf4",
         N);

  memcpy(sk.sl,
         "\x87\x94\x9c\x05\x56\x8a\xa0\xe6\x0f\x27\x40\x44\x95\x33\x1f\x87",
         N);

  memcpy(sk.prf,
         "\xd8\xbb\xa1\xdf\x30\x2d\x6f\xd1\x1e\x55\xd3\x72\x2c\xc3\x04\x44",
         N);

  memcpy(sk.prf,
         "\xbf\xf2\xc4\x40\x71\xfb\x7b\xc8\x82\xa9\xce\x3e\x8e\x43\x9d\xb7",
         N);

  uint8_t message[32] = {0};

  for (int i = 0; i < iterations; i++) {
    shrincs_sign_stateless(message, 32, &sk, sl_signature);
  }
}

void bench_verify_shrincs_stateless(int iterations) {
  SecretKey sk;
  PublicKey pk;

  memcpy(pk.seed,
         "\xa8\xe2\x87\xad\xc1\x50\x1e\xa8\x48\xd9\xe2\x9f\xce\x04\x46\x96",
         N);

  memcpy(pk.root,
         "\x2a\x39\x8e\xeb\x0b\x9f\x7a\xe6\x3d\x80\x0c\xfc\x44\x26\x92\x16",
         N);

  sk.pk = pk;

  memcpy(sk.sf,
         "\x4f\xaf\xef\xab\xe5\x2a\x69\x01\xd3\x37\x89\x1c\xff\x82\xc1\xf4",
         N);

  memcpy(sk.sl,
         "\x87\x94\x9c\x05\x56\x8a\xa0\xe6\x0f\x27\x40\x44\x95\x33\x1f\x87",
         N);

  memcpy(sk.prf,
         "\xd8\xbb\xa1\xdf\x30\x2d\x6f\xd1\x1e\x55\xd3\x72\x2c\xc3\x04\x44",
         N);

  memcpy(sk.prf,
         "\xbf\xf2\xc4\x40\x71\xfb\x7b\xc8\x82\xa9\xce\x3e\x8e\x43\x9d\xb7",
         N);

  uint8_t message[32] = {0};

  for (int i = 0; i < iterations; i++) {
    shrincs_verify(message, 32, sl_signature, SL_SIZE, &pk);
  }
}

uint8_t sf_signature[N + WOTS_SIGN_LEN + N];

void bench_sign_shrincs_stateful(int iterations) {
  SecretKey sk;
  PublicKey pk;
  State state;

  state.valid = 1;

  memcpy(pk.seed,
         "\xa8\xe2\x87\xad\xc1\x50\x1e\xa8\x48\xd9\xe2\x9f\xce\x04\x46\x96",
         N);

  memcpy(pk.root,
         "\x2a\x39\x8e\xeb\x0b\x9f\x7a\xe6\x3d\x80\x0c\xfc\x44\x26\x92\x16",
         N);

  sk.pk = pk;

  memcpy(sk.sf,
         "\x4f\xaf\xef\xab\xe5\x2a\x69\x01\xd3\x37\x89\x1c\xff\x82\xc1\xf4",
         N);

  memcpy(sk.sl,
         "\x87\x94\x9c\x05\x56\x8a\xa0\xe6\x0f\x27\x40\x44\x95\x33\x1f\x87",
         N);

  memcpy(sk.prf,
         "\xd8\xbb\xa1\xdf\x30\x2d\x6f\xd1\x1e\x55\xd3\x72\x2c\xc3\x04\x44",
         N);

  memcpy(sk.prf,
         "\xbf\xf2\xc4\x40\x71\xfb\x7b\xc8\x82\xa9\xce\x3e\x8e\x43\x9d\xb7",
         N);

  uint8_t message[32] = {0};

  for (int i = 0; i < iterations; i++) {
    state.q = 0;
    shrincs_sign_stateful(message, 32, &sk, &state, sf_signature);
  }
}

void bench_verify_shrincs_stateful(int iterations) {
  SecretKey sk;
  PublicKey pk;

  memcpy(pk.seed,
         "\xa8\xe2\x87\xad\xc1\x50\x1e\xa8\x48\xd9\xe2\x9f\xce\x04\x46\x96",
         N);

  memcpy(pk.root,
         "\x2a\x39\x8e\xeb\x0b\x9f\x7a\xe6\x3d\x80\x0c\xfc\x44\x26\x92\x16",
         N);

  sk.pk = pk;

  memcpy(sk.sf,
         "\x4f\xaf\xef\xab\xe5\x2a\x69\x01\xd3\x37\x89\x1c\xff\x82\xc1\xf4",
         N);

  memcpy(sk.sl,
         "\x87\x94\x9c\x05\x56\x8a\xa0\xe6\x0f\x27\x40\x44\x95\x33\x1f\x87",
         N);

  memcpy(sk.prf,
         "\xd8\xbb\xa1\xdf\x30\x2d\x6f\xd1\x1e\x55\xd3\x72\x2c\xc3\x04\x44",
         N);

  memcpy(sk.prf,
         "\xbf\xf2\xc4\x40\x71\xfb\x7b\xc8\x82\xa9\xce\x3e\x8e\x43\x9d\xb7",
         N);

  uint8_t message[32] = {0};
  uint32_t sf_size = N + WOTS_SIGN_LEN + N;

  for (int i = 0; i < iterations; i++) {
    shrincs_verify(message, 32, sf_signature, sf_size, &pk);
  }
}

void bench(void (*func)(int), const char *name, int iterations) {
  clock_t t = clock();
  func(iterations);
  float speed = iterations / ((float)(clock() - t) / CLOCKS_PER_SEC);
  printf("%25s: %8.2f ops/s\n", name, speed);
}

#define BENCH(FUNC, ITER) bench(FUNC, #FUNC, ITER)

int main(void) {
  prepare_msg();

  BENCH(bench_sign_secp256k1, 500);
  BENCH(bench_verify_secp256k1_33, 500);
  BENCH(bench_verify_secp256k1_65, 500);

  BENCH(bench_sign_nist256p1, 500);
  BENCH(bench_verify_nist256p1_33, 500);
  BENCH(bench_verify_nist256p1_65, 500);

  BENCH(bench_sign_ed25519, 4000);
  BENCH(bench_verify_ed25519, 4000);

  BENCH(bench_multiply_curve25519, 4000);

  prepare_node();

  BENCH(bench_ckd, 1000);

  BENCH(bench_sign_shrincs_stateless, 10);
  BENCH(bench_verify_shrincs_stateless, 1000);

  BENCH(bench_sign_shrincs_stateful, 100);
  BENCH(bench_verify_shrincs_stateful, 1000);

  return 0;
}
