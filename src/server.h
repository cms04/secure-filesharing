#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <unistd.h>

#define S_CLOSE_SOCKET(fd) shutdown(fd, SHUT_RDWR); \
                           close(fd)

int init_server(char *ipaddr, uint16_t port);

#endif
