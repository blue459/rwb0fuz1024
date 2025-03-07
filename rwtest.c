#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>

#include "api.h"

extern int crypto_sign_rwb0fuz1024_gmp_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_rwb0fuz1024_gmp(uint8_t *sm, unsigned long long *smlen,
                                       const uint8_t *m, unsigned long long mlen,
                                       const uint8_t *sk);
extern int crypto_sign_rwb0fuz1024_gmp_open(unsigned char *m, unsigned long long *mlen,
                                            const unsigned char *sm, unsigned long long smlen,
                                            const unsigned char *pk);

static uint64_t
time_now() {
  struct timeval tv;

  gettimeofday(&tv, NULL);
  uint64_t r = tv.tv_sec;
  r *= 1000000;
  r += tv.tv_usec;

  return r;
}

int
main(int argc, char **argv) {
  fprintf(stderr, "Generating keypair...\n");

  uint8_t pk[PUBLICKEYBYTES];
  uint8_t sk[SECRETKEYBYTES];

  crypto_sign_rwb0fuz1024_gmp_keypair(pk, sk);

  uint8_t input[BASE];
  uint8_t result[BASE];
  uint8_t output[BASE + BYTES];
  memset(input, 42, BASE);

  fprintf(stderr, "Signing...\n");

  unsigned i;
  uint64_t start_time, end_time;
  unsigned long long outputlen, inputlen;

  static const unsigned sign_its = 1;
  static const unsigned verify_its = 1;

  start_time = time_now();
  for (i = 0; i < sign_its; ++i) {
    crypto_sign_rwb0fuz1024_gmp(output, &outputlen,
                                input, sizeof(input), sk);
  }
  end_time = time_now();
  fprintf(stderr, "  time: %fus\n", ((double) (end_time - start_time)) / sign_its);

  fprintf(stderr, "Verifying...\n");

  start_time = time_now();
  for (i = 0; i < verify_its; ++i) {
    if (crypto_sign_rwb0fuz1024_gmp_open(result, &inputlen,
                                         output, sizeof(output), pk))
      abort();
  }
  end_time = time_now();
  fprintf(stderr, "  time: %fus\n", ((double) (end_time - start_time)) / verify_its);

  return 0;
}
