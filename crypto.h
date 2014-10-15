#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <stdbool.h>
#include <gtk/gtk.h>

#define NONCE_SIZE 2

#define DIFFIE_HELLMAN_G 2
#define DIFFIE_HELLMAN_P 11

#define DIFFIE_HELLMAN_EXP_RANGE 9

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

int get_random_int(int range);
int get_random_prime();
char * get_md5_hash(char *textToHash, long len);
void encrypt_with_key(char *in, char *out, struct Key *key);
void decrypt_with_key(char *in, char *out, struct Key *key);
gboolean are_nonce_bytes_equal(char *nonce1, char *nonce2);
void key_print(struct Key *this);
Key *key_init_new();
void key_free(struct Key *this);
struct Nonce * get_nonce();

#endif
