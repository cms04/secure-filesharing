#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <unistd.h>

#define C_CLOSE_SOCKET(fd) shutdown(fd, SHUT_RDWR); \
                           close(fd)

int init_client(char *ipaddr, uint16_t port);

#endif
