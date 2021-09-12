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
    LOG("Initializing connection...");
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
    LOG("Accepted one connection.");
    LOG("Waiting for the server's publickey...");
    RSA *publickey = c_recv_publickey(fd_client);
    if (publickey == NULL) {
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("c_recv_publickey");
    }
    LOG("Recieved the server's RSA publickey.");
    LOG("Generating an RSA key pair...");
    RSA *key = create_rsa_key();
    if (key == NULL) {
        RSA_free(publickey);
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("create_rsa_key");
    }
    LOG("Key pair successfully generated.");
    if (c_send_publickey(fd_client, key, publickey)) {
        RSA_free(publickey);
        RSA_free(key);
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("c_send_publickey");
    }
    LOG("Your publickey was sended to the server.");
    LOG("Recieving file list...");
    size_t n = 0;
    char **file_list = get_filelist(fd_client, key, &n);
    if (file_list == NULL) {
        RSA_free(publickey);
        RSA_free(key);
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("get_filelist");
    }
    LOG("File list recieved:");
    for (size_t i = 0; i < n; i++) {
        //printf("\t(%ld) %s\n", i+1, get_filename(file_list[i]));
    }
    if (recv_files(file_list, n, fd_client, key)) {
        for (size_t i = 0; i < n; i++) {
            free(file_list[i]);
        }
        free(file_list);
        RSA_free(publickey);
        RSA_free(key);
        CLOSE_SOCKET(fd_client);
        PRINT_ERROR("recv_files");
    }
    for (size_t i = 0; i < n; i++) {
        free(file_list[i]);
    }
    free(file_list);
    RSA_free(key);
    RSA_free(publickey);
    LOG("Closing connection...");
    CLOSE_SOCKET(fd_client);
    LOG("Connection closed.");
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

char **get_filelist(int fd, RSA *privatekey, size_t *n) {
    char *len_string = get_message(fd, privatekey);
    if (len_string == NULL) {
        PRINT_ERROR_RETURN_NULL("get_message");
    }
    *n = atoi(len_string);
    free(len_string);
    char **file_list = (char **) malloc((*n) * sizeof(char *));
    if (file_list == NULL) {
        PRINT_ERROR_RETURN_NULL("malloc");
    }
    for (size_t i = 0; i < (*n); i++) {
        file_list[i] = get_message(fd, privatekey);
        if (file_list[i] == NULL) {
            for (size_t j = 0; j < i; j++) {
                free(file_list[j]);
            }
            free(file_list);
            PRINT_ERROR_RETURN_NULL("get_message");
        }
    }
    return file_list;
}

char *get_filename(char *file_path) {
    char *ptr = file_path, *old_ptr = file_path;
    if ((ptr = strtok(ptr, "/")) == NULL) {
        return file_path;
    }
    old_ptr = ptr;
    while ((ptr = strtok(NULL, "/")) != NULL) {
        old_ptr = ptr;
    }
    return old_ptr;
}

int recv_files(char **file_list, size_t n, int fd, RSA *privatekey) {
    for (size_t i = 0; i < n; i++) {
        FILE *fp = fopen(get_filename(file_list[i]), "w");
        if (fp == NULL) {
            PRINT_ERROR("fopen");
        }
        LOG_RECV_FILENAME(file_list[i]);
        if (recv_file(fp, fd, privatekey, NULL)) {
            fclose(fp);
            PRINT_ERROR("send_file");
        }
        fclose(fp);
    }
    return EXIT_SUCCESS;
}
