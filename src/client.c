#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

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
    RSA *publickey = c_recv_publickey(fd_client);
    if (publickey == NULL) {
        C_CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    RSA_free(publickey);
    C_CLOSE_SOCKET(fd_client);
    return EXIT_SUCCESS;
}

RSA *c_recv_publickey(int fd) {
    char buf[4096];
    bzero(buf, 4096);
    int bytes_rcv = recv(fd, buf, 4095, 0);
    if (bytes_rcv < 0) {
        return NULL;
    }
    printf("\n\n%s\n\n", buf);
    FILE *fp = fopen("recieved.key", "w+");
    if (fp == NULL) {
        return NULL;
    }
    fwrite(buf, sizeof(char), bytes_rcv, fp);
    fseek(fp, 0, SEEK_SET);
    RSA *publickey = RSA_new();
    if (publickey == NULL) {
        fclose(fp);
        unlink("recieved.key");
        return NULL;
    }
    if (PEM_read_RSAPublicKey(fp, &publickey, NULL, NULL) == NULL) {
        RSA_free(publickey);
        fclose(fp);
        unlink("recieved.key");
        return NULL;
    }
    fclose(fp);
    unlink("recieved.key");
    return publickey;
}
