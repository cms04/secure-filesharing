#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

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
    RSA *key = s_create_rsa_key();
    if (s_send_publickey(fd_client, key)) {
        RSA_free(key);
        S_CLOSE_SOCKET(fd_server);
        S_CLOSE_SOCKET(fd_client);
        return EXIT_FAILURE;
    }
    RSA_free(key);
    S_CLOSE_SOCKET(fd_client);
    S_CLOSE_SOCKET(fd_server);
    return EXIT_SUCCESS;
}

RSA *s_create_rsa_key(void) {
    RSA *key = RSA_new();
    if (key == NULL) {
        return NULL;
    }
    srand(time(NULL));
    BIGNUM *e = BN_new();
    if (e == NULL) {
        RSA_free(key);
        return NULL;
    }
    if (!BN_set_word(e, RSA_F4)) {
        RSA_free(key);
        BN_clear_free(e);
        return NULL;
    }
    if (!RSA_generate_key_ex(key, 4096, e, NULL)) {
        RSA_free(key);
        BN_clear_free(e);
        return NULL;
    }
    BN_clear_free(e);
    return key;
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
    PEM_write_RSAPublicKey(fp, publickey);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char buf[len];
    bzero(buf, len);
    fread(buf, sizeof(char), len, fp);
    int bytes_sent = send(fd, buf, len, 0);
    if (bytes_sent < 0) {
        RSA_free(publickey);
        return EXIT_FAILURE;
    }
    fclose(fp);
    unlink("sended.key");
    RSA_free(publickey);
    return EXIT_SUCCESS;
}
