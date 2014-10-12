#include "crypto.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/blowfish.h>
#include <string.h>
#include <gtk/gtk.h>

#define SIZE 16

int padding = RSA_PKCS1_PADDING;
const char *secretKey = "AAAAAAAAAAAAAAAA"; // 128 bits

void encrypt(unsigned char *in, unsigned char *out)
{
    unsigned char ivec[8] = {};
    BF_KEY *key = malloc(sizeof(BF_KEY));

    BF_set_key(key, strlen(secretKey), (const unsigned char*)secretKey );

    BF_cbc_encrypt(in, out, strlen((char *)in), key, ivec, BF_ENCRYPT);
    printf("%s\n", out);
}

void decrypt(unsigned char *in, unsigned char *out)
{
    unsigned char ivec[8] = {};
    BF_KEY *key = malloc(sizeof(BF_KEY));

    BF_set_key(key, strlen(secretKey), (const unsigned char*)secretKey );

    BF_cbc_encrypt(in, out, strlen((char *)in), key, ivec, BF_DECRYPT);
    printf("%s\n", out);
}

unsigned char * get_nonce()
{
    unsigned char *nonce = malloc(NONCE_SIZE);
    RAND_bytes(nonce, NONCE_SIZE);
    return nonce;
}

gboolean are_nonces_equal(unsigned char *nonce1, unsigned char *nonce2)
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

RSA * createRSA(Key * key, int public)
{
    if(key->rsa != NULL)
    {
        return key->rsa;
    }

    if(public)
    {
        key->rsa = d2i_RSAPublicKey(NULL, (const unsigned char **)&key->data, key->length);
    }
    else
    {
        key->rsa = d2i_RSAPrivateKey(NULL, (const unsigned char **)&key->data, key->length);
    }

    if(key->rsa == NULL)
    {
        printf("ENEORNEONER\n");
    }
    else
    {
        int size = RSA_size(key->rsa);
        printf("RSA SIZE: %d\n", size);
    }

    return key->rsa;
}

bool generate_key(Key *publicKey, Key *privateKey)
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
 
    unsigned long   e = RSA_F4;
 
    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
 
    r = RSA_new();
    ret = RSA_generate_key_ex(r, KEY_BITS, bne, NULL);
    if(ret != 1){
        goto free_all;
    }

    publicKey->length = i2d_RSAPublicKey(r, &publicKey->data);
    printf("publickeylength: %d\n", publicKey->length);
    publicKey->rsa = r;
    privateKey->length = i2d_RSAPrivateKey(r, &privateKey->data);
    printf("private length: %d\n", privateKey->length);
    privateKey->rsa = r;

    // 4. free
free_all:
    BN_free(bne);
 
    return (ret == 1);
}

int public_encrypt(unsigned char * data,int data_len,Key *key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa == NULL)
    {
        printf("MOTHER FUCKER\n");
        return 0;
    }

    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

int public_decrypt(unsigned char * enc_data,int data_len,Key *key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

int private_encrypt(unsigned char * data,int data_len,Key *key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;

}
int private_decrypt(unsigned char * enc_data,int data_len,Key *key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}