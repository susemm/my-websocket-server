#ifndef __WEB_SOCKET_H
#define __WEB_SOCKET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERR_OOM -2
#define ERR_EOF -1

/*-------------------------------------------------------------------
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
--------------------------------------------------------------------*/
#define FIN_OK      0x01
#define FIN_CONT    0x00

#define OPCODE_CONTIUATION  0x00    /* denotes a continuation frame */
#define OPCODE_TEXT         0x01    /* denotes a text frame, should encoding with utf-8 */
#define OPCODE_BINARY       0x02    /* denotes a binary frame */
#define OPCODE_DISCONNECT   0x08    /* denotes a connection close */
#define OPCODE_PING         0x09    /* denotes a ping */
#define OPCODE_PONG         0x0a    /* denotes a pong */

typedef struct
{
    uint8_t FIN:1;
    uint8_t RSV1:1;
    uint8_t RSV2:1;
    uint8_t RSV3:1;
    uint8_t opcode:4;

    uint8_t MASK:1;
    uint8_t payload_len:7;
} frame_head_common_t __attribute__((packed));

typedef struct
{
    frame_head_common_t head;
    uint32_t mask;
    uint8_t payload[0];
} frame_uint8_t __attribute__((packed));

typedef struct
{
    frame_head_common_t head;
    uint16_t payload_length;
    uint32_t mask;
    uint8_t payload[0];
} frame_uint16_t __attribute__((packed));

typedef struct
{
    frame_head_common_t head;
    uint64_t payload_length;
    uint32_t mask;
    uint8_t payload[0];
} frame_uint64_t __attribute__((packed));

typedef struct _frame_head {
    char fin;
    char opcode;
    char mask;
    unsigned long long payload_length;
    char masking_key[4];
} frame_head_t;

int ws_shakeHands(int fd);
int ws_recvFrameHead(int fd, frame_head_t * head);
int ws_recvPayload(int fd, frame_head_t * head, uint8_t ** payload);
int ws_sendFrameHead(int fd, uint64_t payload_length);

#ifdef __cplusplus
}
#endif

#endif /* __WEB_SOCKET_H */
