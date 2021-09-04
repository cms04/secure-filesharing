#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

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

#endif
