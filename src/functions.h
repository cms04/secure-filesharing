#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <openssl/rsa.h>
#include <stdio.h>

int send_file(FILE *fp, int fd, RSA *otherkey);
int recv_file(FILE *fp, int fd, RSA *key, ssize_t *len);
RSA *create_rsa_key(void);

#endif
