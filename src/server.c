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

int init_server(char *ipaddr, uint16_t port, char **file_list, size_t n) {
    LOG("Initializing server...");
    int fd_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_server == 0) {
        PRINT_ERROR("socket");
    }
    struct sockaddr_in server_addr;
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ipaddr);
    server_addr.sin_port = htons(port);
    if (bind(fd_server, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        CLOSE_SOCKET(fd_server);
        PRINT_ERROR("bind");
    }
    if (listen(fd_server, 0) < 0) {
        CLOSE_SOCKET(fd_server);
        PRINT_ERROR("listen");
    }
    LOG("Server started.");
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    LOG("Waiting for connections...");
    int fd_client = accept(fd_server, (struct sockaddr *) &client_addr, &client_len);
    if (fd_client < 0) {
        CLOSE_SOCKET(fd_server);
        PRINT_ERROR("accept");
    }
    LOG("Accepted one connection.");
    LOG("Generating an RSA key pair...");
    RSA *key = create_rsa_key();
    if (key == NULL) {
        CLOSE_2_SOCKETS(fd_client, fd_server);
        PRINT_ERROR("create_rsa_key");
    }
    LOG("Your key pair was generated successfully.");
    LOG("Send your publickey to the client...");
    if (s_send_publickey(fd_client, key)) {
        RSA_free(key);
        CLOSE_2_SOCKETS(fd_client, fd_server);
        PRINT_ERROR("s_send_publickey");
    }
    LOG("Your publickey was sended successfully.");
    LOG("Waiting for the client's publickey...");
    RSA *publickey = s_recv_publickey(fd_client, key);
    if (publickey == NULL) {
        RSA_free(key);
        CLOSE_2_SOCKETS(fd_client, fd_server);
        PRINT_ERROR("s_recv_publickey");
    }
    LOG("Publickey successfully recieved");
    LOG("Sending file list...");
    if (send_filelist(file_list, n, fd_client, publickey)) {
        RSA_free(key);
        RSA_free(publickey);
        CLOSE_2_SOCKETS(fd_client, fd_server);
        PRINT_ERROR("send_filelist");
    }
    LOG("File list was sended successfully");
    for (size_t i = 0; i < n; i++) {
        printf("\t(%ld) %s\n", i+1, file_list[i]);
    }
    if (send_files(file_list, n, fd_client, publickey)) {
        RSA_free(key);
        RSA_free(publickey);
        CLOSE_2_SOCKETS(fd_client, fd_server);
        PRINT_ERROR("send_files");
    }
    RSA_free(publickey);
    RSA_free(key);
    LOG("Closing connection...");
    CLOSE_2_SOCKETS(fd_client, fd_server);
    LOG("Connection closed.");
    return EXIT_SUCCESS;
}

int s_send_publickey(int fd, RSA *key) {
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
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *) malloc(len * sizeof(char));
    if (buf == NULL) {
        RSA_free(publickey);
        FCLOSE_UNLINK(fp, "sended.key");
        PRINT_ERROR("malloc");
    }
    bzero(buf, len);
    snprintf(buf, len - 1, "%ld", len);
    if (send(fd, buf, 15, 0) < 0) {
        RSA_free(publickey);
        FCLOSE_UNLINK(fp, "sended.key");
        free(buf);
        PRINT_ERROR("send");
    }
    bzero(buf, len);
    fread(buf, sizeof(char), len, fp);
    int bytes_sent = send(fd, buf, len, 0);
    free(buf);
    if (bytes_sent < 0) {
        RSA_free(publickey);
        FCLOSE_UNLINK(fp, "sended.key");
        PRINT_ERROR("send");
    }
    FCLOSE_UNLINK(fp, "sended.key");
    RSA_free(publickey);
    return EXIT_SUCCESS;
}

RSA *s_recv_publickey(int fd, RSA *key) {
    FILE *fp = fopen("recieved.key", "w+");
    if (fp == NULL) {
        PRINT_ERROR_RETURN_NULL("fopen");
    }
    if (recv_file(fp, fd, key, NULL)) {
        FCLOSE_UNLINK(fp, "recieved.key");
        PRINT_ERROR_RETURN_NULL("recv_file");
    }
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

int send_filelist(char **file_list, size_t n, int fd, RSA *publickey) {
    char len_string[LEN_BUFFER_SIZE];
    bzero(len_string, LEN_BUFFER_SIZE);
    snprintf(len_string, LEN_BUFFER_SIZE - 1, "%ld", n);
    if (send_message(fd, len_string, publickey)) {
        PRINT_ERROR("send_message");
    }
    for (size_t i = 0; i < n; i++) {
        if (send_message(fd, file_list[i], publickey)) {
            PRINT_ERROR("send_message");
        }
    }
    return EXIT_SUCCESS;
}

int send_files(char **file_list, size_t n, int fd, RSA *publickey) {
    for (size_t i = 0; i < n; i++) {
        FILE *fp = fopen(file_list[i], "r");
        if (fp == NULL) {
            PRINT_ERROR("fopen");
        }
        LOG_SEND_FILENAME(file_list[i]);
        if (send_file(fp, fd, publickey, NULL)) {
            fclose(fp);
            PRINT_ERROR("send_file");
        }
        fclose(fp);
    }
    return EXIT_SUCCESS;
}
