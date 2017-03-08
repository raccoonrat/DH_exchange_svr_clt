#include <string.h>
#include <stdio.h>
#include "dhsocket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

int dhsocket_init(dhsocket_t* this)
{
    this->cfd = 0;
    this->sfd = socket(AF_INET, SOCK_STREAM, 0);
    return (this->sfd < 0);
}

int dhsocket_serv_start(dhsocket_t* this, unsigned int port)
{
    struct sockaddr_in serv_addr =
    {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = htonl(INADDR_ANY)
        },
        .sin_port = htons(port)
    };

    bind(this->sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    return listen(this->sfd, 0) >= 0;
}

void dhsocket_serv_accept(dhsocket_t* this)
{
    this->cfd = accept(this->sfd, NULL, NULL);
}

int dhsocket_client_start(dhsocket_t* this, const char* addr, unsigned int port)
{
    struct sockaddr_in serv_addr =
    {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = inet_addr(addr)
        },
        .sin_port = htons(port)
    };

    return connect(this->sfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) >= 0;
}

void dhsocket_send(int sfd, msg_codes code, void* buf, unsigned int size)
{
    int ret = 0;
    dhpacket_t *p = new(1,sizeof(dhpacket_t)+size);
    if(!p)
        return;
    p->code = code;
    memcpy(p->data, buf, size);
    ret = send(sfd, p, sizeof(dhpacket_t)+size, 0);
    /*
        if (write(sfd, p, sizeof(dhpacket_t)+size) != sizeof(dhpacket_t)+size)
        */
    if(ret == -1)
    {
        printf( "send() failed: %s", strerror(errno));
    }
    delete(p, sizeof(dhpacket_t)+size);
}

void dhsocket_recv(int sfd, void* buf, unsigned int size)
{
    dhpacket_t *p = new(1,sizeof(dhpacket_t)+size);
    if(!p)
        return;
    recv(sfd, p, sizeof(dhpacket_t)+size, 0);
    memcpy(buf,p->data,size);
    delete(p, sizeof(dhpacket_t)+size);
}


int dhsocket_recv_exp(int sfd, void* buf, unsigned int size, msg_codes exp)
{
    int ret = 0;
    dhpacket_t *p = new(1,sizeof(dhpacket_t)+size);
    if(!p)
        return -1;

    ret = recv(sfd, p, sizeof(dhpacket_t)+size, 0);
    if(ret ==0 || ret == -1)
    {
        printf("recv() failed: %s\n", strerror(errno));
        return -1;
    }
    /*read(sfd, p, sizeof(dhpacket_t)+size);*/
    if(p->code!=exp)
        return -1;
    memcpy(buf,p->data,size);
    delete(p, sizeof(dhpacket_t)+size);
    return 0;
}

void dhsocket_close(dhsocket_t* this)
{
    shutdown(this->sfd,SHUT_WR);
    close(this->sfd);
}



/*
 * dhsocket_resolvename()
 * Convert a symbolic host name to numeric, #.#.#.# format.
 *
 * INPUT    : hostnm, host name
 * OUTPUT   : hostnm, numeric represantaion of the input host name.
 * RETURN   : a pointer to an IP number on success
 *        NULL on failure.
 */
char *
dhsocket_resolvename(char *hostnm)
{
    char    *ip;    /* internet number to be returned */
    int     cnt;    /* number of hosts returned by gethostbyname() */
    int     rnd;    /* number of randomly chosen host */
    struct hostent  *host;
    char    *s;

    host = gethostbyname(hostnm);
    if (host == NULL)
    {
        return(NULL);
    }
    ip = (char *)malloc((size_t)1024 + 1);
    if (ip == NULL)
    {
        return(NULL);
    }
    /*
     * If multiple host address are returned choose one randomly
     */
    for (cnt=0; host->h_addr_list[cnt] != NULL; cnt++)
        ;      /* just count */

    rnd = 0;
    (void)strcpy(ip, (char *)inet_ntoa(*(struct in_addr *)host->h_addr_list[rnd]));

    return(ip);
}


