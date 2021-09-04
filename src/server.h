#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <unistd.h>
#include <openssl/rsa.h>

#define S_CLOSE_SOCKET(fd) shutdown(fd, SHUT_RDWR); \
                           close(fd)

int init_server(char *ipaddr, uint16_t port);
RSA *s_create_rsa_key(void);
int s_send_publickey(int fd, RSA *key);
RSA *s_recv_publickey(int fd, RSA *key);

#endif
