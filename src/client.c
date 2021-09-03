#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "client.h"

int init_client(char *ipaddr, uint16_t port) {
    int fd_client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_client < 0) {
        return EXIT_SUCCESS;
    }
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ipaddr);
    server_addr.sin_port = htons(port);
    if (connect(fd_client, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        C_CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    char buf[15];
    bzero(buf, 15);
    int bytes_rcv = recv(fd_client, buf, 14, 0);
    if (bytes_rcv < 0) {
        C_CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    C_CLOSE_SOCKET(fd_client);
    printf("%s\n", buf);
    return EXIT_SUCCESS;
}
