#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <unistd.h>
#include <openssl/rsa.h>

#define C_CLOSE_SOCKET(fd) shutdown(fd, SHUT_RDWR); \
                           close(fd)

int init_client(char *ipaddr, uint16_t port);
RSA *c_recv_publickey(int fd);
int c_send_publickey(int fd, RSA *key, RSA *otherkey);
int c_send_file(FILE *fp, int fd, RSA *otherkey);

#endif
