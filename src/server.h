#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <unistd.h>
#include <openssl/rsa.h>

#define LEN_BUFFER_SIZE 10

int init_server(char *ipaddr, uint16_t port, char **file_list, size_t n);
RSA *s_create_rsa_key(void);
int s_send_publickey(int fd, RSA *key);
RSA *s_recv_publickey(int fd, RSA *key);
int send_filelist(char **file_list, size_t n, int fd, RSA *publickey);
int send_files(char **file_list, size_t n, int fd, RSA *publickey);

#endif
