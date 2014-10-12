#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <stdbool.h>
#include <openssl/rsa.h>
#include <gtk/gtk.h>

#define KEY_BITS 1024
#define NONCE_SIZE 2

#define DHG 10
#define DHP 541

// This will change if bits changes
#define PUBLIC_KEY_LENGTH 270
#define PRIVATE_KEY_LENGTH 1191

typedef struct Key
{
    unsigned char *data;
    int length;
    RSA *rsa;
} Key;

void encrypt(char *in, char *out);
void decrypt(char *in, char *out);
gboolean are_nonces_equal(char *nonce1, char *nonce2);
void key_print(struct Key *this);
Key *key_init_new();
void key_free(struct Key *this);
bool generate_key(struct Key *publicKey, struct Key *privateKey);
int public_encrypt(unsigned char * data,int data_len, struct Key * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len, struct Key * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len, struct Key * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len, struct Key * key, unsigned char *decrypted);
char * get_nonce();

#endif
