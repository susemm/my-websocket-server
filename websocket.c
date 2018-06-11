#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h> /* for base64 */
#include <openssl/evp.h>

#include "websocket.h"

#define SOCK_MTU            1500
#define BUFFER_SIZE         1500 /* default MTU size */
#define SHA_DIGEST_LENGTH   1500
#define GUID                "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


int base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length-1] = '\0';
    size = bptr->length;

    BIO_free_all(bio);
    return size;
}

/**
 * @brief _readline
 * read a line string from all buffer
 * @param allbuf
 * @param level
 * @param linebuf
 * @return
 */
int _readline(char* allbuf,int level,char* linebuf)
{
    int len = strlen(allbuf);
    for (;level<len;++level)
    {
        if(allbuf[level]=='\r' && allbuf[level+1]=='\n')
        {
            return level+2;
        }
        else
        {
            *(linebuf++) = allbuf[level];
        }
    }
    return -1;
}

/**
 * @brief umask
 * xor decode
 * @param data
 * @param len
 * @param mask
 */
void umask(char *data, int len, char *mask)
{
    int i;
    for (i=0; i<len; ++i)
    {
        *(data+i) ^= *(mask+(i%4));
    }
}

int ws_shakeHands(int fd)
{
    //next line's point num
    int level = 0;
    //all request data
    char buffer[BUFFER_SIZE];
    //a line data
    char linebuf[256];
    //Sec-WebSocket-Accept
    char sec_accept[32];
    //sha1 data
    unsigned char sha1_data[SHA_DIGEST_LENGTH+1]={0};
    //reponse head buffer
    char head[BUFFER_SIZE] = {0};

    if (read(fd, buffer, sizeof(buffer)) <= 0)
    {
        perror("read");
    }
    printf("request\n");
    printf("%s\n", buffer);

    do {
        memset(linebuf, 0, sizeof(linebuf));
        level = _readline(buffer, level,linebuf);
        //printf("line:%s\n",linebuf);

        if (strstr(linebuf, "Sec-WebSocket-Key") != NULL)
        {
            strcat(linebuf, GUID);
//            printf("key:%s\nlen=%d\n",linebuf+19,strlen(linebuf+19));
            SHA1((unsigned char*)&linebuf+19, strlen(linebuf+19), (unsigned char*)&sha1_data);
//            printf("sha1:%s\n",sha1_data);
            base64_encode(sha1_data, strlen(sha1_data), sec_accept);
//            printf("base64:%s\n",sec_accept);
            /* write the response */
            sprintf(head, "HTTP/1.1 101 Switching Protocols\r\n" \
                          "Upgrade: websocket\r\n" \
                          "Connection: Upgrade\r\n" \
                          "Sec-WebSocket-Accept: %s\r\n" \
                          "\r\n", sec_accept);

            printf("response\n");
            printf("%s", head);
            if (write(fd, head, strlen(head))<0)
            {
                perror("write");
            }

            break;
        }
    } while((buffer[level]!='\r' || buffer[level+1]!='\n') && level!=-1);

    return 0;
}

int ws_recvFrameHead(int fd, frame_head_t * head)
{
    char one_char;
    /*read fin and op code*/
    if (read(fd,&one_char,1)<=0)
    {
        perror("read fin~~");
        return -1;
    }
    head->fin = (one_char & 0x80) == 0x80;
    head->opcode = one_char & 0x0F;
    if (read(fd,&one_char,1)<=0)
    {
        perror("read mask");
        return -1;
    }
    head->mask = (one_char & 0x80) == 0X80;

    /*get payload length*/
    head->payload_length = one_char & 0x7F;

    if (head->payload_length == 126)
    {
        char extern_len[2];
        if (read(fd,extern_len,2)<=0)
        {
            perror("read extern_len");
            return -1;
        }
        head->payload_length = (extern_len[0]&0xFF) << 8 | (extern_len[1]&0xFF);
    }
    else if (head->payload_length == 127)
    {
        char extern_len[8],temp;
        int i;
        if (read(fd,extern_len,8)<=0)
        {
            perror("read extern_len");
            return -1;
        }
        for(i=0;i<4;i++)
        {
            temp = extern_len[i];
            extern_len[i] = extern_len[7-i];
            extern_len[7-i] = temp;
        }
        memcpy(&(head->payload_length),extern_len,8);
    }

    /*read masking-key*/
    if (read(fd,head->masking_key,4)<=0)
    {
        perror("read masking-key");
        return -1;
    }

    return 0;
}

int ws_recvPayload(int fd, frame_head_t * head, uint8_t ** payload)
{
    int ret = 0;
    uint32_t left = head->payload_length;
    uint32_t offset = 0;
    uint8_t * pl = NULL;

    pl = (uint8_t *)malloc(head->payload_length);
    if (NULL == pl)
    {
        return ERR_OOM;
    }

    while (left > 0)
    {
        ret = read(fd, &(pl[offset]), left);
        if (ret <= 0)
        {
            break;
        }

        offset += ret;
        left -= ret;
    }

    if (left > 0) /* not complete */
    {
        free(pl);
        pl = NULL;
        return ERR_EOF;
    }

    if (head->mask)
    {
        umask(pl, offset, head->masking_key);
    }

    *payload = pl;

    return offset;
}

int ws_sendFrameHead(int fd, uint64_t payload_length)
{
    char response_head[12] = {0};
    int head_length = 0;

    if (payload_length < 126)
    {
        response_head[0] = 0x81;
        response_head[1] = (uint8_t)(payload_length & 0xff);
        head_length = 2;
    }
    else if (payload_length < 0xFFFF)
    {
        response_head[0] = 0x81;
        response_head[1] = 126;
        response_head[2] = (uint8_t)((payload_length >> 8) & 0xFF);
        response_head[3] = (uint8_t) (payload_length       & 0xFF);
        head_length = 4;
    }
    else
    {
        //no code
        response_head[0] = 0x81;
        response_head[1] = 127;
        response_head[2] = (uint8_t)((payload_length >> 56) & 0xFF);
        response_head[3] = (uint8_t)((payload_length >> 48) & 0xFF);
        response_head[4] = (uint8_t)((payload_length >> 40) & 0xFF);
        response_head[5] = (uint8_t)((payload_length >> 32) & 0xFF);
        response_head[6] = (uint8_t)((payload_length >> 24) & 0xFF);
        response_head[7] = (uint8_t)((payload_length >> 16) & 0xFF);
        response_head[8] = (uint8_t)((payload_length >>  8) & 0xFF);
        response_head[9] = (uint8_t) (payload_length        & 0xFF);
        head_length = 12;
    }

    if (write(fd, response_head, head_length) <= 0)
    {
        perror("write head");
        return -1;
    }

    return 0;
}

void ws_getRandomString(uint8_t * buf, uint32_t len)
{
    uint32_t i;
    uint8_t temp;

    srand((int)time(0));

    for(i = 0; i < len; i++)
    {
        temp = (uint8_t)(rand() & 0xFF);
        if(temp == 0)   // 0x00 may cause string termiated
        {
            temp = 0xFF;
        }
        buf[i] = temp;
    }
}
