#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcp.h"

int passive_server(int port, int queue)
{
    ///define sockfd
    int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    ///define sockaddr_in
    struct sockaddr_in server_sockaddr;
    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_port = htons(port);
    server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    ///bind, return 0 for sucess, -1 for failure
    if (bind(server_sockfd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) == -1)
    {
        perror("bind");
        exit(1);
    }
    ///listen, return 0 for sucess, -1 for failure
    if (listen(server_sockfd, queue) == -1)
    {
        perror("listen");
        exit(1);
    }
    printf("Listening on port: %d\n",port);
    return server_sockfd;
}
