#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#define LOG(text) printf("[✔] %s\n", text)
#define LOG_BLOCKS(sum) printf("[✔] Sending %ld blocks...\n\n", sum)
#define LOG_RECIEVING(sum) printf("[✔] Recieving %ld blocks...\n\n", sum)
#define LOG_SEND_FILENAME(filename) printf("[✔] Sending file: %s...\n\n", filename)
#define LOG_RECV_FILENAME(filename) printf("[✔] Recieving file: %s...\n\n", filename)
#define LOG_PROGRESS(part, sum) printf("\033[A\r\tSended block %ld of %ld\t\t(%3.0f percent)\n", part, sum, 100 * ((float) part) / sum)
#define LOG_RECIEVED(part, sum) printf("\033[A\r\tRecieved block %ld of %ld\t\t(%3.0f percent)\n", part, sum, 100 * ((float) part) / sum)

#define ERROR_OPENSSL(function) fprintf(stderr, "ERROR: %s() failed at %s, line %d: %s\n", function, __FILE__, __LINE__, ERR_error_string(ERR_get_error(), NULL)); \
                                return EXIT_FAILURE

#define ERROR_OPENSSL_RETURN_NULL(function) fprintf(stderr, "ERROR: %s() failes at %s, line %d: %s\n", function, __FILE__, __LINE__, ERR_error_string(ERR_get_error(), NULL)); \
                                            return NULL

#define PRINT_ERROR(function) fprintf(stderr, "ERROR: %s() failed at %s, line %d: %s\n", function, __FILE__, __LINE__, strerror(errno)); \
                              return EXIT_FAILURE

#define PRINT_ERROR_RETURN_NULL(function) fprintf(stderr, "ERROR: %s() failed at %s, line %d: %s\n", function, __FILE__, __LINE__, strerror(errno)); \
                                          return NULL

#define CLOSE_SOCKET(fd) shutdown(fd, SHUT_RDWR); \
                         close(fd)

#define CLOSE_2_SOCKETS(fd1, fd2) CLOSE_SOCKET(fd1); \
                                  CLOSE_SOCKET(fd2)

#define FCLOSE_UNLINK(fp, filename) fclose(fp); \
                                    unlink(filename)

int send_file(FILE *fp, int fd, RSA *otherkey, ssize_t *len);
int recv_file(FILE *fp, int fd, RSA *key, ssize_t *len);
RSA *create_rsa_key(void);
int send_message(int fd, char *msg, RSA *publickey);
char *get_message(int fd, RSA *privatekey);
size_t block_len(char *block, size_t block_len);

#endif
