#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <unistd.h>

#include "client.h"
#include "functions.h"

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
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    RSA *publickey = c_recv_publickey(fd_client);
    if (publickey == NULL) {
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    RSA *key = create_rsa_key();
    if (key == NULL) {
        RSA_free(publickey);
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    if (c_send_publickey(fd_client, key, publickey)) {
        RSA_free(publickey);
        RSA_free(key);
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    RSA_free(key);
    RSA_free(publickey);
    CLOSE_SOCKET(fd_client);
    return EXIT_SUCCESS;
}

RSA *c_recv_publickey(int fd) {
    char *buf = (char *) malloc(4096 * sizeof(char));
    if (buf == NULL) {
        return NULL;
    }
    bzero(buf, 4096);
    int bytes_rcv = recv(fd, buf, 4095, 0);
    if (bytes_rcv < 0) {
        free(buf);
        return NULL;
    }
    FILE *fp = fopen("recieved.key", "w+");
    if (fp == NULL) {
        free(buf);
        return NULL;
    }
    fwrite(buf, sizeof(char), bytes_rcv, fp);
    free(buf);
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

int c_send_publickey(int fd, RSA *key, RSA *otherkey) {
    RSA *publickey = RSAPublicKey_dup(key);
    if (publickey == NULL) {
        return EXIT_FAILURE;
    }
    FILE *fp = fopen("sended.key", "w+");
    if (fp == NULL) {
        RSA_free(publickey);
        return EXIT_FAILURE;
    }
    if (!PEM_write_RSAPublicKey(fp, publickey)) {
        RSA_free(publickey);
        fclose(fp);
        unlink("sended.key");
        return EXIT_FAILURE;
    }
    int status = send_file(fp, fd, otherkey, NULL);
    fclose(fp);
    unlink("sended.key");
    RSA_free(publickey);
    return status;
}
