#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "server.h"
#include "functions.h"

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
        CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    if (listen(fd_server, 0) < 0) {
        CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int fd_client = accept(fd_server, (struct sockaddr *) &client_addr, &client_len);
    if (fd_client < 0) {
        CLOSE_SOCKET(fd_server);
        return EXIT_FAILURE;
    }
    RSA *key = create_rsa_key();
    if (key == NULL) {
        CLOSE_SOCKET(fd_server);
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    if (s_send_publickey(fd_client, key)) {
        RSA_free(key);
        CLOSE_SOCKET(fd_server);
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    RSA *publickey = s_recv_publickey(fd_client, key);
    if (publickey == NULL) {
        RSA_free(key);
        CLOSE_SOCKET(fd_server);
        CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }

    FILE *fp = fopen("server_got.msg", "w");
    recv_file(fp, fd_client, key, NULL);
    fclose(fp);
    fp = fopen("server.msg", "w+");
    fprintf(fp, "Hallo Client!");
    send_file(fp, fd_client, publickey, NULL);
    fclose(fp);
    unlink("server.msg");


    RSA_free(publickey);
    RSA_free(key);
    CLOSE_SOCKET(fd_client);
    CLOSE_SOCKET(fd_server);
    return EXIT_SUCCESS;
}

int s_send_publickey(int fd, RSA *key) {
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
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *) malloc(len * sizeof(char));
    if (buf == NULL) {
        RSA_free(publickey);
        fclose(fp);
        unlink("sended.key");
        return EXIT_FAILURE;
    }
    bzero(buf, len);
    snprintf(buf, len - 1, "%ld", len);
    if (send(fd, buf, 15, 0) < 0) {
        RSA_free(publickey);
        fclose(fp);
        unlink("sended.key");
        free(buf);
        return EXIT_FAILURE;
    }
    bzero(buf, len);
    fread(buf, sizeof(char), len, fp);
    int bytes_sent = send(fd, buf, len, 0);
    free(buf);
    if (bytes_sent < 0) {
        RSA_free(publickey);
        fclose(fp);
        unlink("sended.key");
        return EXIT_FAILURE;
    }
    fclose(fp);
    unlink("sended.key");
    RSA_free(publickey);
    return EXIT_SUCCESS;
}

RSA *s_recv_publickey(int fd, RSA *key) {
    FILE *fp = fopen("recieved.key", "w+");
    if (fp == NULL) {
        return NULL;
    }
    if (recv_file(fp, fd, key, NULL)) {
        fclose(fp);
        unlink("recieved.key");
        return NULL;
    }
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
