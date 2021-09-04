#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <openssl/rsa.h>
#include <stdio.h>

#define CLOSE_SOCKET(fd) shutdown(fd, SHUT_RDWR); \
                         close(fd)

int send_file(FILE *fp, int fd, RSA *otherkey, ssize_t *len);
int recv_file(FILE *fp, int fd, RSA *key, ssize_t *len);
RSA *create_rsa_key(void);

#endif
