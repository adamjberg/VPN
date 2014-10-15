#include "crypto.h"
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/blowfish.h>
#include <string.h>
#include <gtk/gtk.h>

#include "utils.h"

int get_random_int(int range)
{
    return rand() % range;
}

int get_random_prime()
{
    char *s;
    BIGNUM *bn = BN_new();
    BN_generate_prime_ex(bn, 32, 1, NULL, NULL, NULL);
    s = BN_bn2hex(bn);
    unsigned int prime = strtol(s, NULL, 16);
    free(s);
    BN_free(bn);
    return prime;
}

char *get_md5_hash(char *textToHash, long len)
{
    char *out = malloc(MD5_DIGEST_LENGTH);
    MD5((unsigned char *)textToHash, len, (unsigned char *)out);
    return out;
}

void encrypt_with_key(char *in, char *out, Key *key)
{
    int num = 0;
    unsigned char ivec[8] = {};
    BF_KEY *bf_key = malloc(sizeof(BF_KEY));

    BF_set_key(bf_key, key->length, (const unsigned char *)key->data );

    BF_cfb64_encrypt((unsigned char *)in, (unsigned char *)out, strlen(in), bf_key, ivec, &num, BF_ENCRYPT);
}

void decrypt_with_key(char *in, char *out, Key *key)
{
    int num = 0;
    unsigned char ivec[8] = {};
    BF_KEY *bf_key = malloc(sizeof(BF_KEY));

    BF_set_key(bf_key, key->length, (const unsigned char *)key->data );

    BF_cfb64_encrypt((unsigned char *)in, (unsigned char *)out, strlen(in), bf_key, ivec, &num, BF_DECRYPT);
}

Nonce *get_nonce()
{
    Nonce *nonce = malloc(sizeof(Nonce));
    RAND_bytes((unsigned char *)&nonce->bytes, NONCE_SIZE - 1);
    nonce->bytes[NONCE_SIZE - 1] = 0;
    getHex(nonce->bytes, nonce->hex, NONCE_SIZE);
    return nonce;
}

gboolean are_nonce_bytes_equal(char *nonce1, char *nonce2)
{
    int i;
    for (i = 0; i < NONCE_SIZE; i++)
    {
        if (nonce1[i] != nonce2[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

Key *key_init_new()
{
    Key *this = malloc(sizeof(Key));
    this->data = NULL;
    this->length = 0;
    return this;
}

void key_free(Key *this)
{
    free(this->data);
    free(this);
}