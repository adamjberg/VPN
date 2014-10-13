#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/blowfish.h>
#include <string.h>
#include <gtk/gtk.h>
#include <linux/random.h>

#define SIZE 16

int padding = RSA_PKCS1_PADDING;

void encrypt(char *in, char *out, Key *key)
{
    unsigned char ivec[8] = {};
    BF_KEY *bf_key = malloc(sizeof(BF_KEY));

    BF_set_key(bf_key, key->length, (const unsigned char*)key->data );

    BF_cbc_encrypt((unsigned char *)in, (unsigned char *)out, strlen((char *)in), bf_key, ivec, BF_ENCRYPT);
}

void decrypt(char *in, char *out, Key *key)
{
    unsigned char ivec[8] = {};
    BF_KEY *bf_key = malloc(sizeof(BF_KEY));

    BF_set_key(bf_key, key->length, (const unsigned char*)key->data );

    BF_cbc_encrypt((unsigned char *)in, (unsigned char *)out, strlen((char *)in), bf_key, ivec, BF_DECRYPT);
}

char * get_nonce()
{
    char *nonce = malloc(NONCE_SIZE);
    RAND_bytes((unsigned char *)nonce, NONCE_SIZE - 1);
    nonce[NONCE_SIZE - 1] = 0;
    return nonce;
}

gboolean are_nonces_equal(char *nonce1, char *nonce2)
{
    int i;
    for(i = 0; i < NONCE_SIZE; i++)
    {
        if(nonce1[i] != nonce2[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

void key_print(Key *this)
{
    int i;
    printf("KEY LENGTH : %d\n", this->length);
    for(i = 0; i < this->length; i++)
    {
        printf("%02x", this->data[i]);
    }
    printf("\nENDKEY\n");
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