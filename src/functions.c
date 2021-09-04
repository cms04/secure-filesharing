#include <openssl/bn.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "functions.h"

RSA *create_rsa_key(void) {
    RSA *key = RSA_new();
    if (key == NULL) {
        ERROR_OPENSSL_RETURN_NULL("RSA_new");
    }
    srand(time(NULL));
    BIGNUM *e = BN_new();
    if (e == NULL) {
        RSA_free(key);
        ERROR_OPENSSL_RETURN_NULL("BN_new");
    }
    if (!BN_set_word(e, RSA_F4)) {
        RSA_free(key);
        BN_clear_free(e);
        ERROR_OPENSSL_RETURN_NULL("BN_set_word");
    }
    if (!RSA_generate_key_ex(key, 4096, e, NULL)) {
        RSA_free(key);
        BN_clear_free(e);
        ERROR_OPENSSL_RETURN_NULL("RSA_generate_key_ex");
    }
    BN_clear_free(e);
    return key;
}

int send_file(FILE *fp, int fd, RSA *otherkey, ssize_t *len) {
    fseek(fp, 0, SEEK_END);
    ssize_t msg_len = ftell(fp);
    if (len != NULL) {
        *len = msg_len;
    }
    fseek(fp, 0, SEEK_SET);
    size_t rsa_size = RSA_size(otherkey);
    size_t block_size = rsa_size - 42;
    ssize_t block_count = msg_len / block_size + 1;
    char *crypt = (char *) malloc(rsa_size * sizeof(char));
    if (crypt == NULL) {
        PRINT_ERROR("malloc");
    }
    bzero(crypt, rsa_size);
    char *block = (char *) malloc(block_size * sizeof(char));
    if (block == NULL) {
        free(crypt);
        PRINT_ERROR("malloc");
    }
    bzero(block, block_size);
    snprintf(block, block_size - 1, "%ld", block_count);
    if (RSA_public_encrypt(block_size, (unsigned char *) block, (unsigned char *) crypt, otherkey, RSA_PKCS1_OAEP_PADDING) < 0) {
        free(crypt);
        free(block);
        ERROR_OPENSSL("RSA_public_encrypt");
    }
    int bytes_sent = send(fd, crypt, rsa_size, 0);
    if (bytes_sent < 0) {
        free(crypt);
        free(block);
        PRINT_ERROR("send");
    }
    for (size_t i = 0; i < block_count; i++) {
        bzero(block, block_size);
        fread(block, sizeof(char), block_size, fp);
        if (RSA_public_encrypt(block_size, (unsigned char *) block, (unsigned char *) crypt, otherkey, RSA_PKCS1_OAEP_PADDING) < 0) {
            free(crypt);
            free(block);
            ERROR_OPENSSL("RSA_public_encrypt");
        }
        if (send(fd, crypt, rsa_size, 0) < 0) {
            free(crypt);
            free(block);
            PRINT_ERROR("send");
        }
    }
    free(block);
    free(crypt);
    return EXIT_SUCCESS;
}

int recv_file(FILE *fp, int fd, RSA *key, ssize_t *len) {
    size_t rsa_size = RSA_size(key);
    size_t block_size = rsa_size - 42;
    char *crypt = (char *) malloc(rsa_size * sizeof(char));
    if (crypt == NULL) {
        PRINT_ERROR("malloc");
    }
    bzero(crypt, rsa_size);
    char *block = (char *) malloc(block_size * sizeof(char));
    if (block == NULL) {
        free(crypt);
        PRINT_ERROR("malloc");
    }
    bzero(block, block_size);
    if (recv(fd, crypt, rsa_size, 0) < 0) {
        free(crypt);
        free(block);
        PRINT_ERROR("recv");
    }
    if (RSA_private_decrypt(rsa_size, (unsigned char *) crypt, (unsigned char *) block, key, RSA_PKCS1_OAEP_PADDING) < 0) {
        free(crypt);
        free(block);
        ERROR_OPENSSL("RSA_private_decrypt");
    }
    ssize_t block_count = strtoull(block, NULL, 10);
    for (ssize_t i = 0; i < block_count; i++) {
        bzero(crypt, rsa_size);
        if (recv(fd, crypt, rsa_size, 0) < 0) {
            free(crypt);
            free(block);
            PRINT_ERROR("recv");
        }
        bzero(block, block_size);
        if (RSA_private_decrypt(rsa_size, (unsigned char *) crypt, (unsigned char *) block, key, RSA_PKCS1_OAEP_PADDING) < 0) {
            free(crypt);
            free(block);
            ERROR_OPENSSL("RSA_private_decrypt");
        }
        fwrite(block, sizeof(char), block_size, fp);
    }
    if (len != NULL) {
        *len = ftell(fp);
    }
    free(crypt);
    free(block);
    return EXIT_SUCCESS;
}
