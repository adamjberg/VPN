#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <stdbool.h>
#include <gtk/gtk.h>

#define KEY_BITS 1024
#define NONCE_SIZE 2

#define DIFFIE_HELLMAN_G 10
#define DIFFIE_HELLMAN_P 541

// This will change if bits changes
#define PUBLIC_KEY_LENGTH 270
#define PRIVATE_KEY_LENGTH 1191

typedef struct Key
{
    char *data;
    int length;
} Key;

typedef struct Nonce
{
    char bytes[NONCE_SIZE];
    char hex[NONCE_SIZE * 2];
} Nonce;

char * get_md5_hash(char *textToHash, long len);
void encrypt(char *in, char *out, struct Key *key);
void decrypt(char *in, char *out, struct Key *key);
gboolean are_nonce_bytes_equal(char *nonce1, char *nonce2);
void key_print(struct Key *this);
Key *key_init_new();
void key_free(struct Key *this);
struct Nonce * get_nonce();

#endif
