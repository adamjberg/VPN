#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/pem.h>
#include <openssl/rsa.h>

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
RSA * generate_key_pair();

#endif
