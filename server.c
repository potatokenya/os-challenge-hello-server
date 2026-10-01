#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>
#define LONESHA256_IMPLEMENTATION
#include "lonesha256.h"

int main(int argc, char *argv[])
{
    char *end;
    long port;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    errno = 0;
    port = strtol(argv[1], &end, 10);

    if (errno != 0 || end == argv[1] || *end != '\0' ||
        port < 1 || port > 65535) {
        fprintf(stderr, "Port must be between 1 and 65535.\n");
        return EXIT_FAILURE;
    }

    /* Create an IPv4 TCP socket. */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    /* Allow the server to reuse its address after restarting. */
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse)) == -1) {
        perror("setsockopt");
        close(server_fd);
        return EXIT_FAILURE;
    }

    /* Listen on the selected port on all local IPv4 interfaces. */
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((unsigned short)port);

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) == -1) {
        perror("bind");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 128) == -1) {
        perror("listen");
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("Listening on port %ld...\n", port);

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);

        if (client_fd == -1) {
            if (errno == EINTR)
                continue;
            perror("accept");
            close(server_fd);
            return EXIT_FAILURE;
        }

        unsigned char request[49];
size_t received = 0;

/* TCP may deliver the request in several pieces. */
while (received < sizeof(request)) {
    ssize_t n = recv(client_fd,
                     request + received,
                     sizeof(request) - received,
                     0);

    if (n == -1) {
        if (errno == EINTR)
            continue;
        perror("recv");
        break;
    }

    if (n == 0) {
        fprintf(stderr, "Client disconnected before sending a full request.\n");
        break;
    }

    received += (size_t)n;
}

if (received == sizeof(request)) {
    uint64_t start_network;
    uint64_t end_network;

    memcpy(&start_network, request + 32, sizeof(start_network));
    memcpy(&end_network, request + 40, sizeof(end_network));

    uint64_t start = be64toh(start_network);
    uint64_t end = be64toh(end_network);
    unsigned int priority = request[48];

    printf("Request: start=%" PRIu64
           ", end=%" PRIu64
           ", priority=%u\n",
           start, end, priority);
uint64_t answer = 0;
int found = 0;

/* Search from start up to, but not including, end. */
for (uint64_t candidate = start; candidate < end; candidate++) {
    unsigned char hash[32];

    /* The client hashes an 8-byte little-endian integer. */
    uint64_t input = htole64(candidate);

    if (lonesha256(hash, (const unsigned char *)&input,
                   sizeof(input)) != 0) {
        fprintf(stderr, "SHA-256 failed.\n");
        break;
    }

    if (memcmp(hash, request, sizeof(hash)) == 0) {
        answer = candidate;
        found = 1;
        break;
    }
}

if (found) {
    /* The response must use big-endian network byte order. */
    uint64_t response = htobe64(answer);
    const unsigned char *bytes = (const unsigned char *)&response;
    size_t sent = 0;

    while (sent < sizeof(response)) {
        ssize_t n = send(client_fd, bytes + sent,
                         sizeof(response) - sent, MSG_NOSIGNAL);

        if (n == -1) {
            if (errno == EINTR)
                continue;
            perror("send");
            break;
        }

        if (n == 0) {
            fprintf(stderr, "Could not finish sending the answer.\n");
            break;
        }

        sent += (size_t)n;
    }

    if (sent == sizeof(response))
        printf("Answer sent: %" PRIu64 "\n", answer);
} else {
    fprintf(stderr, "No answer found in the supplied range.\n");}
}

close(client_fd);
    }
}