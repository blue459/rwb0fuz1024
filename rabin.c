
/* @<Preamble@>= */
/* @<Standard includes@>= */

#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>


#include <gmp.h>
#include <openssl/sha.h>

#include "api.h"

extern void randombytes(uint8_t*buffer, unsigned long long length);

/* @<Preamble@> */
/* @<Key gen...@>= */
/* @<Random pr...@>= */

static void
init_random_prime(mpz_t n, unsigned size, unsigned mod8){
    uint8_t buffer[256];
    const unsigned bytes= size>>3;

    if(bytes==0||bytes> sizeof(buffer))
        abort();

    mpz_init2(n, size);

    int count = 0;
    for(;;){
        count++;
        randombytes(buffer, bytes);

        buffer[bytes-1]&= ~7;
        buffer[bytes-1]|= mod8;
        mpz_import(n, bytes, 1, 1, 0, 0, buffer);

        int ret = mpz_probab_prime_p(n, 48);
        if(ret > 0) {
            printf("prime test: %d\n", count);
            break;
        }
    }
}

/* @<Random prime generation@>@; */

/* @<Hash function@>= */
static void
hash(mpz_t e, const uint8_t*m, unsigned mlen){
    uint8_t element[128];
    uint8_t counter[4]= {0};

    SHA512_CTX shactx;
    SHA512_Init(&shactx);
    SHA512_Update(&shactx, m, mlen);
    SHA512_Update(&shactx, counter, sizeof(counter));
    SHA512_Final(element, &shactx);

    counter[3]= 1;
    SHA512_Init(&shactx);
    SHA512_Update(&shactx, element, 64);
    SHA512_Update(&shactx, counter, sizeof(counter));
    SHA512_Final(element+64, &shactx);

    element[0]= 0;

    mpz_init(e);
    mpz_import(e, 128, 1, 1, 1, 0, element);
}
/* @<Hash function@>@; */

/* @<HMAC function@>= */
static uint8_t
HMAC_SHA512(const uint8_t*key,
            const uint8_t*value, unsigned valuelen){
    unsigned i;
    uint8_t keycopy[128];

    for(i= 0;i<128;++i)
        keycopy[i]= 0x5c;

    for(i= 0;i<8;++i)
        keycopy[i]^= key[i];

    SHA512_CTX shactx;
    SHA512_Init(&shactx);
    SHA512_Update(&shactx, keycopy, 128);
    SHA512_Update(&shactx, value, valuelen);

    uint8_t t[64];
    SHA512_Final(t, &shactx);

    for(i= 0;i<128;++i)
        keycopy[i]^= (0x5c^0x36);

    SHA512_Init(&shactx);
    SHA512_Update(&shactx, keycopy, 128);
    SHA512_Update(&shactx, t, sizeof(t));
    SHA512_Final(t, &shactx);

    return t[0];
}
/* @<HMAC function@>@; */

/* @<Extended...@>= */
static void
xgcd(mpz_t u, mpz_t v, mpz_t ip, mpz_t iq){
    mpz_t p, q;
    mpz_init_set(p, ip);
    mpz_init_set(q, iq);

    mpz_init_set_ui(u, 1);
    mpz_init_set_ui(v, 0);

    mpz_t x, y;
    mpz_init_set_ui(x, 0);
    mpz_init_set_ui(y, 1);

    mpz_t s, t;
    mpz_init(s);
    mpz_init(t);

    while(mpz_sgn(q)){
        mpz_set(t, q);
        mpz_fdiv_qr(s, q, p, q);
        mpz_set(p, t);

        mpz_set(t, x);
        mpz_mul(x, s, x);
        mpz_sub(x, u, x);
        mpz_set(u, t);

        mpz_set(t, y);
        mpz_mul(y, s, y);
        mpz_sub(y, v, y);
        mpz_set(v, t);
    }

    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(s);
    mpz_clear(t);
}
/* @<Extended Euclid@>@; */

/* @<Key pair func...@>= */
int
crypto_sign_rwb0fuz1024_gmp_keypair(uint8_t*pk, uint8_t*sk){
    mpz_t p, q, n;

    /* @<Pick primes@>= */
    for(;;){
        init_random_prime(p, BASE*8, 3);
        init_random_prime(q, BASE*8, 7);
        mpz_init(n);
        mpz_mul(n, p, q);

        if(mpz_scan1(n, BASE*16-8)!=ULONG_MAX){
            gmp_printf("p: %Zd\n", p);
            gmp_printf("q: %Zd\n", q);
            gmp_printf("n: %Zd\n", n);
            break;
        }

        mpz_clear(n);
        mpz_clear(p);
        mpz_clear(q);
    }
    /*   @<Pick primes@>@; */

    /* @<Chinese remainder precom...@>= */
    mpz_t u, v;
    xgcd(u, v, p, q);
    mpz_mul(u, u, p);

    /*   @<Chinese remainder precomputation@>@; */

    /* @<Generate HMAC secret@>= */
    uint8_t hmac_secret[8];
    randombytes(hmac_secret, sizeof(hmac_secret));

    /*   @<Generate HMAC secret@>@; */

    /* @<Keypair serial...@>= */
    memset(sk, 0, SECRETKEYBYTES);
    mpz_export(sk, NULL, -1, 8, -1, 0, p);
    mpz_export(sk+BASE, NULL, -1, 8, -1, 0, q);
    mpz_export(sk+BASE*2, NULL, -1, 8, -1, 0, u);
    sk[BASE*4]= mpz_sgn(u)<0?1:0;
    memcpy(sk+BASE*4+1, hmac_secret, sizeof(hmac_secret));

    memset(pk, 0, PUBLICKEYBYTES);
    mpz_export(pk, NULL, -1, 8, -1, 0, n);

    /*   @<Keypair serialisation@>@; */

    /* @ @<Keypair cleanup@>= */
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(u);
    mpz_clear(v);
    /*   @<Keypair cleanup@>@; */

    return 0;
}
/* @<Key pair function@>@; */

/* @<Key generation@> */

/* @<Signature generation@>= */

/* @<Quadratic r...@>= */
static int
is_quadratic_residue(mpz_t e, mpz_t p, mpz_t power){
    mpz_t r, reduced_e;
    mpz_init(r);
    mpz_init(reduced_e);

    mpz_mod(reduced_e, e, p);

    mpz_powm(r, e, power, p);
    mpz_mul(r, r, r);
    mpz_mod(r, r, p);

    const int result= 0==mpz_cmp(r, reduced_e);
    mpz_clear(r);
    mpz_clear(reduced_e);

    return result;
}
/* @<Quadratic residue test function@>@; */

/* @<Signature comp...@>= */
static void
signature_compress(mpz_t zsig, mpz_t s, mpz_t n){
    mpz_t vs[4];
    mpz_init_set_ui(vs[0], 0);
    mpz_init_set_ui(vs[1], 1);
    mpz_init(vs[2]);
    mpz_init(vs[3]);

    mpz_t root;
    mpz_init(root);
    mpz_sqrt(root, n);

    mpz_t cf;
    mpz_init(cf);

    unsigned i= 1;

    do{
        i= (i+1)&3;

        if(i&1){
            mpz_fdiv_qr(cf, s, s, n);
        }else{
            mpz_fdiv_qr(cf, n, n, s);
        }
        mpz_mul(vs[i], vs[(i-1)&3], cf);
        mpz_add(vs[i], vs[i], vs[(i-2)&3]);
    }while(mpz_cmp(vs[i], root)<0);

    mpz_init(zsig);
    mpz_set(zsig, vs[(i-1)&3]);

    mpz_clear(root);
    mpz_clear(cf);
    mpz_clear(vs[0]);
    mpz_clear(vs[1]);
    mpz_clear(vs[2]);
    mpz_clear(vs[3]);
}
/* @<Signature compression function@>@; */

/* @<Signing function@>= */
int
crypto_sign_rwb0fuz1024_gmp(uint8_t*sm, unsigned long long*smlen,
                            const uint8_t*m, unsigned long long mlen,
                            const uint8_t*sk){
    mpz_t p, q, u, v, n;

    /* @<Import secret key@>= */
    mpz_init(p);
    mpz_init(q);
    mpz_init(u);
    mpz_init(v);

    mpz_import(p, 8, -1, 8, -1, 0, sk);
    mpz_import(q, 8, -1, 8, -1, 0, sk+BASE);
    mpz_import(u, 16, -1, 8, -1, 0, sk+BASE*2);
    if(sk[BASE*4])
        mpz_neg(u, u);

    mpz_init(n);
    mpz_mul(n, p, q);

    mpz_set_ui(v, 1);
    mpz_sub(v, v, u);
    /*   @<Import secret key@>@; */

    /* @ @<Hash message@>= */
    mpz_t elem;
    hash(elem, m, mlen);
    /*   @<Hash message@>@; */

    /* @<Testing for residues@>= */
    mpz_t pp1over4, qp1over4;

    mpz_init_set(pp1over4, p);
    mpz_add_ui(pp1over4, pp1over4, 1);
    mpz_cdiv_q_2exp(pp1over4, pp1over4, 2);

    mpz_init_set(qp1over4, q);
    mpz_add_ui(qp1over4, qp1over4, 1);
    mpz_cdiv_q_2exp(qp1over4, qp1over4, 2);

    int a= is_quadratic_residue(elem, p, pp1over4);
    int b= is_quadratic_residue(elem, q, qp1over4);
    /*   @<Testing for residues@>@; */

    /* @<Calculate tweaks@>= */
    int mul_2= 0, negate= 0;

    if(a^b){
        mul_2= 1;
        a^= 1;
    }

    if(!a)
        negate= 1;
    /*   @<Calculate tweaks@>@; */

    /* @<Apply tweaks@>= */
    if(negate)
        mpz_neg(elem, elem);

    if(mul_2)
        mpz_mul_2exp(elem, elem, 1);

    if(negate||mul_2)
        mpz_mod(elem, elem, n);

    /* @<Signing function@>= */

    /* @<Pick root@>= */
    const uint8_t r = HMAC_SHA512(sk+257, m, mlen);
    /*   @<Pick root@>@; */

    /* @<Calculate root@>= */
    mpz_t proot, qroot;

    mpz_init_set(proot, elem);
    mpz_powm(proot, elem, pp1over4, p);

    mpz_init_set(qroot, elem);
    mpz_powm(qroot, elem, qp1over4, q);

    if(r&1)
        mpz_neg(proot, proot);
    if(r&2)
        mpz_neg(qroot, qroot);

    mpz_mul(proot, proot, v);
    mpz_mul(qroot, qroot, u);
    mpz_add(proot, proot, qroot);
    mpz_mod(proot, proot, n);
    /*   @<Calculate root@>@; */

    /* @<Compress signature@>= */
    mpz_t zsig;
    signature_compress(zsig, proot, n);
    /*   @<Compress signature@>@; */

    /* @<Export signed message@>= */
    memset(sm, 0, BYTES-1);
    sm[BYTES-1]= (mul_2<<1)|negate;
    mpz_export(sm, NULL, -1, 1, 1, 0, zsig);
    memcpy(sm+BYTES, m, mlen);
    *smlen= mlen+BYTES;
    /*   @<Export signed message@>@; */

    /* @ @<Signing cleanup@>= */
    mpz_clear(zsig);
    mpz_clear(n);
    mpz_clear(proot);
    mpz_clear(qroot);
    mpz_clear(pp1over4);
    mpz_clear(qp1over4);
    mpz_clear(elem);
    mpz_clear(u);
    mpz_clear(v);
    mpz_clear(p);
    mpz_clear(q);
    /*   @<Signing cleanup@>@; */

    return 0;
}
/* @<Signing function@>@; */

/* @<Signature generation@> */

/* @<Signature Verification@>= */
int
crypto_sign_rwb0fuz1024_gmp_open(unsigned char*m, unsigned long long*mlen,
                                 const unsigned char*sm, unsigned long long smlen,
                                 const unsigned char*pk){
    int res= 0;

    /* @ @<Import values for ver...@>= */
    if(smlen < BYTES)
        return -1;

    mpz_t n, zsig;

    mpz_init(n);
    mpz_import(n, BASE/4, -1, 8, -1, 0, pk);
    mpz_init(zsig);
    mpz_import(zsig, BASE, -1, 1, 1, 0, sm);
    const uint8_t negate= sm[BYTES-1]&1;
    const uint8_t mul_2= sm[BYTES-1]&2;
    /*   @<Import values for verification@>@; */

    /* @ @<Hash signed message@>= */
    mpz_t elem;
    hash(elem, sm+BYTES, smlen-BYTES);
    /*   @<Hash signed message@>@; */

    /* @<Apply tweaks@>= */
    if(negate)
        mpz_neg(elem, elem);

    if(mul_2)
        mpz_mul_2exp(elem, elem, 1);

    if(negate||mul_2)
        mpz_mod(elem, elem, n);
    /*   @<Apply tweaks@>@; */

    /* @<Verify compressed signature@>= */
    mpz_mul(zsig, zsig, zsig);
    mpz_mul(zsig, zsig, elem);
    mpz_mod(zsig, zsig, n);

    if(0==mpz_sgn(zsig)){
        res= -1;
        goto out;
    }

    if(!mpz_perfect_square_p(zsig)){
        res= -1;
        goto out;
    }
    /*   @<Verify compressed signature@>@; */


    *mlen= smlen-BYTES;
    memcpy(m, sm+BYTES, *mlen);

  out:
    mpz_clear(zsig);
    mpz_clear(elem);
    mpz_clear(n);

    return res;
}
/* @<Signature Verification@> */
