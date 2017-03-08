#ifndef DH_SOCKET_H
#define DH_SOCKET_H

#include "dhutils.h"

struct dhsocket
{
    int sfd;
    int cfd;
};
typedef struct dhsocket dhsocket_t;

typedef enum
{
    MSG_KEY_DH_GEX_REQUEST = 0x00,
    MSG_KEX_DH_GEX_INIT = 0x01,
    MSG_KEX_DH_GEX_INIT_ACK = 0x02,
    MSG_KEX_DH_GEX_GROUP = 0x03,
    MSG_KEX_DH_GEX_GROUP_ACK = 0x04,
    MSG_KEX_DH_GEX_REPLY = 0x05,
    MSG_KEX_DH_GEX_REPLY_ACK = 0x06,
    MSG_KEX_DH_GEX_VERIFY = 0x07,
    MSG_KEX_DH_GEX_VERIFY_ACK = 0x08,
    MSG_KEX_DH_GEX_INTERIM = 0x09
} msg_codes;

struct dhpacket
{
    msg_codes code;
    /*
        size_t len;
    */
    uint32_t len;
    byte data[];
};
typedef struct dhpacket dhpacket_t;

int     dhsocket_init(dhsocket_t*);
int     dhsocket_serv_start(dhsocket_t*, unsigned int);
void    dhsocket_serv_accept(dhsocket_t*);
int     dhsocket_client_start(dhsocket_t*, const char*, unsigned int);
void    dhsocket_send(int, msg_codes, void*, unsigned int);
void    dhsocket_recv(int, void*, unsigned int);
int     dhsocket_recv_exp(int sfd, void*, unsigned int, msg_codes);
void    dhsocket_close(dhsocket_t*);

#endif
