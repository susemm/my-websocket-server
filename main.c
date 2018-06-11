#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>          /* See NOTES */
#include <arpa/inet.h>
#include <sys/socket.h>

#include "websocket.h"
#include "tcp.h"


#define PORT 9000

int main()
{
    int ser_fd = passive_server(PORT, 20);

    struct sockaddr_in client_addr;
    socklen_t addr_length = sizeof(client_addr);
    int conn = accept(ser_fd,(struct sockaddr*)&client_addr, &addr_length);

    ws_shakeHands(conn);

    int count = 10;
    while (count--)
    {
        frame_head_t head;
        uint8_t * payload_data = NULL;

        int ret = ws_recvFrameHead(conn, &head);
        if (ret < 0)
        {
            break;
        }

        printf("fin=%d\nopcode=0x%X\nmask=%d\npayload_len=%llu\n",
            head.fin,
            head.opcode,
            head.mask,
            head.payload_length);
        if (OPCODE_DISCONNECT == head.opcode) {
            break;
        }

        // read payload data
        ret = ws_recvPayload(conn, &head, &payload_data);
        if (ret < 0)
        {
            break;
        }

        printf("recive:%s", payload_data);

        //echo data
        ws_sendFrameHead(conn, head.payload_length);
        ret = write(conn, payload_data, ret);
        free(payload_data);
        if (ret <= 0)
        {
            break;
        }

        printf("\n-----------\n");
    }

    close(conn);
    close(ser_fd);

    return 0;
}
