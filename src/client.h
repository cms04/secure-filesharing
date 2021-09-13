#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <unistd.h>
#include <openssl/rsa.h>

#define LEN_BUFFER_SIZE 10

int init_client(char *ipaddr, uint16_t port);
RSA *c_recv_publickey(int fd);
int c_send_publickey(int fd, RSA *key, RSA *otherkey);
int c_send_file(FILE *fp, int fd, RSA *otherkey);
char **get_filelist(int fd, RSA *privatekey, size_t *n);
char *get_filename(char *file_path);
int recv_files(char **file_list, size_t n, int fd, RSA *privatekey);
char **get_filenames(char **file_paths, size_t n);

#endif
