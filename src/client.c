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
        PRINT_ERROR("socket");
    }
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ipaddr);
    server_addr.sin_port = htons(port);
    if (connect(fd_client, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("connect");
    }
    RSA *publickey = c_recv_publickey(fd_client);
    if (publickey == NULL) {
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("c_recv_publickey");
    }
    RSA *key = create_rsa_key();
    if (key == NULL) {
        RSA_free(publickey);
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("create_rsa_key");
    }
    if (c_send_publickey(fd_client, key, publickey)) {
        RSA_free(publickey);
        RSA_free(key);
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("c_send_publickey");
    }

    FILE *fp = fopen("client.msg", "w+");
    fprintf(fp, "Hallo Server!");
    send_file(fp, fd_client, publickey, NULL);
    FCLOSE_UNLINK(fp, "client.msg");
    fp = fopen("client_got.msg", "w");
    recv_file(fp, fd_client, key, NULL);
    fclose(fp);

    RSA_free(key);
    RSA_free(publickey);
    CLOSE_SOCKET(fd_client);
    return EXIT_SUCCESS;
}

RSA *c_recv_publickey(int fd) {
    char len_string[16];
    bzero(len_string, 16);
    if (recv(fd, len_string, 15, 0) < 0) {
        PRINT_ERROR_RETURN_NULL("recv");
    }
    size_t len = strtoul(len_string, NULL, 10);
    char *buf = (char *) malloc(len * sizeof(char));
    if (buf == NULL) {
        PRINT_ERROR_RETURN_NULL("malloc");
    }
    bzero(buf, len);
    int bytes_rcv = recv(fd, buf, len, 0);
    if (bytes_rcv < 0) {
        free(buf);
        PRINT_ERROR_RETURN_NULL("recv");
    }
    FILE *fp = fopen("recieved.key", "w+");
    if (fp == NULL) {
        free(buf);
        PRINT_ERROR_RETURN_NULL("fopen");
    }
    fwrite(buf, sizeof(char), bytes_rcv, fp);
    free(buf);
    fseek(fp, 0, SEEK_SET);
    RSA *publickey = RSA_new();
    if (publickey == NULL) {
        FCLOSE_UNLINK(fp, "recieved.key");
        ERROR_OPENSSL_RETURN_NULL("RSA_new");
    }
    if (PEM_read_RSAPublicKey(fp, &publickey, NULL, NULL) == NULL) {
        RSA_free(publickey);
        FCLOSE_UNLINK(fp, "recieved.key");
        ERROR_OPENSSL_RETURN_NULL("PEM_read_RSAPublicKey");
    }
    FCLOSE_UNLINK(fp, "recieved.key");
    return publickey;
}

int c_send_publickey(int fd, RSA *key, RSA *otherkey) {
    RSA *publickey = RSAPublicKey_dup(key);
    if (publickey == NULL) {
        ERROR_OPENSSL("RSAPublicKey_dup");
    }
    FILE *fp = fopen("sended.key", "w+");
    if (fp == NULL) {
        RSA_free(publickey);
        PRINT_ERROR("fopen");
    }
    if (!PEM_write_RSAPublicKey(fp, publickey)) {
        RSA_free(publickey);
        FCLOSE_UNLINK(fp, "sended.key");
        ERROR_OPENSSL("PEM_write_RSAPublicKey");
    }
    if (send_file(fp, fd, otherkey, NULL)) {
        FCLOSE_UNLINK(fp, "sended.key");
        RSA_free(publickey);
        PRINT_ERROR("send_file");
    }
    FCLOSE_UNLINK(fp, "sended.key");
    RSA_free(publickey);
    return EXIT_SUCCESS;
}
