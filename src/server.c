#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include "server.h"

int init_server(char *ipaddr, uint16_t port) {
    int fd_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_server == 0) {
        return EXIT_FAILURE;
    }
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ipaddr);
    server_addr.sin_port = htons(port);
    if (bind(fd_server, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        S_CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    if (listen(fd_server, 0) < 0) {
        S_CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int fd_client = accept(fd_server, (struct sockaddr *) &client_addr, &client_len);
    if (fd_client < 0) {
        S_CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    char *msg = "Hello World!";
    int bytes_sent = send(fd_client, msg, strlen(msg), 0);
    if (bytes_sent < 0) {
        S_CLOSE_SOCKET(fd_client);
        S_CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    S_CLOSE_SOCKET(fd_client);
    S_CLOSE_SOCKET(fd_server);
    return EXIT_SUCCESS;
}
