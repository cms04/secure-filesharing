#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>

#include "server.h"
#include "client.h"

int main(int argc, char *const *argv) {
    char *ipaddr = NULL;
    uint16_t port = 0;
    bool is_server = false;
    extern char *optarg;
    extern int optind;
    char param = -1;
    while ((param = getopt(argc, argv, "a:p:s")) != EOF) {
        switch (param) {
            case 'a':
                ipaddr = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 's':
                is_server = true;
                break;
            default:
                fprintf(stderr, "Invalid parameter -%c\n", param);
                break;
        }
    }
    if (ipaddr == NULL || port == 0) {
        fprintf(stderr, "ERROR: You have to set an IP-adress and a port.\n");
        return EXIT_FAILURE;
    }
    size_t n = argc - optind;
    if (is_server && n == 0) {
        fprintf(stderr, "ERROR: I need some files to send.\n");
        return EXIT_FAILURE;
    }
    char **file_list = (char **) malloc(n * sizeof(char *));
    if (file_list == NULL) {
        fprintf(stderr, "ERROR: No memory available...\n");
        return EXIT_FAILURE;
    }
    for (size_t i = 0; optind < argc; optind++, i++) {
        file_list[i] = argv[optind];
    }
    int status = is_server ? init_server(ipaddr, port, file_list, n) : init_client(ipaddr, port);
    free(file_list);
    return status;
}
