#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <sys/socket.h>
#include <netinet/tcp.h>

#include <string.h>
#include <stdlib.h>

#include <string.h>
#include <stdlib.h>

#include <tux_ztdh.h>
#include <dhsocket.h>
#include <tas.h>

int64_t total_bytes_read = 0;
int64_t total_messages_read = 0;
int64_t total_connect_num = 0;
int64_t total_success_num = 0;
int64_t total_failed_num = 0;

/**
 * Struct to carry around connection (client)-specific data.
 */
typedef struct client_ctx
{
    GPE_DH_CONTEXT_T *nzdh_clt_ctx;
    AES_GCM_HANDLE_P_T aes_gcm_handle;
    /* Here you can add your own application-specific attributes which
     * are connection-specific. */
} client_ctx_t;

static int generate_clt_pubkey(GPE_DH_CONTEXT_T **nzdh_clt_ctx)
{
    zterr err;
    unsigned int ksize = sizeof(dhParamsBER128);

    int cc = 0;
    int sc = 0;
    unsigned int minP;
    unsigned int iP;
    unsigned int maxP;

    GPE_DH_CONTEXT_T *clt_ctx = NULL;

    minP = 256;
    iP = 414;   /* TUXEDO NZSDK static prime argument defined in tux_ztdh.h*/
    maxP = 4096;

    if(nzdh_clt_ctx == NULL)
    {
        err |= TZTCA_ERR_INIT;
        goto err_ret;
    }
    err = ztca_Init(FALSE);
    if (err != ZTERR_OK)
    {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        err |= TZTCA_ERR_INIT;
        goto err_ret;
    }
    /* start TUX NZ DH protocol, generate the first package with client public key */
    {
        /*step 1: nzdh_KeyAgreePhase1 include ztca_GenerateKey, ztca_CreatePubKeyCtx and ztca_DHGenPubValue*/
        char errmsg[215] = "";
        err = nzdh_KeyAgreePhase1(ksize, (GPE_DH_CONTEXT_T**)nzdh_clt_ctx);
        clt_ctx = *nzdh_clt_ctx;
#ifdef DEBUG
        sprintf(errmsg, ">[%s:%d:%s] pid(%d)Pubkey with client",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, clt_ctx->publicValue , clt_ctx->publicValueLen);
        try_continue(0,1);
        sprintf(errmsg, "nzdh_KeyAgreePhase1 key size %d, pubkey size %d", ksize,clt_ctx->publicValueLen);
        TZTCA_PRN_STAT(errmsg, err);
#endif
    }
    return err;
err_ret:
    poll(0,0,100);  /* wait .1s */
    err = ztca_Shutdown();
    if (err != ZTERR_OK)
    {
        TZTCA_PRN_RES("ztca_Shutdown - ", TZTCA_ERR_SHUTDOWN & err);
        err = TZTCA_ERR_INIT;
    }
    printf("[%s:%d:%s]ztca_Shutdown -\n", __FILE__,__LINE__,__func__);
    return err;
}

static void set_tcp_no_delay(evutil_socket_t fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               &one, sizeof one);
}

static void timeoutcb(evutil_socket_t fd, short what, void *arg)
{
    struct event_base *base = arg;
    printf("timeout, fd=%d\n",fd);

    event_base_loopexit(base, NULL);
}

#if !defined(offsetof)
#define offsetof(_type, _member) \
    (((char *)&((_type *)0)->_member) - (char *)((_type *)0))
#endif
static void readcb(struct bufferevent *bev, void *ctx)
{
    unsigned int ksize = sizeof(dhParamsBER128);
    zterr err;

    GPE_DH_CONTEXT_T *nzdh_clt_ctx = NULL;
    unsigned char    *agreedSecrets = NULL; /* Agreed key SEND*/
    unsigned char    *agreedSecretr = NULL; /* Agreed key receive */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    unsigned int      agreedSecretLenr; /* The length of the pn */
    unsigned int      spacetozero = 0;  /* Length of space to NULL */
    AES_GCM_HANDLE_P_T handle=NULL;
    int               send_len = 0;

    ztcaData other ;
    size_t bs =0;
    size_t size_out = 0;
    int ret =0;
    size_t size_in = 0, remain =0;
    dhpacket_t *mete_header = NULL;
    dhpacket_t *data_in = NULL;
    dhpacket_t *data_used = NULL;
    dhpacket_t *send_pkg = NULL;
    char errmsg[215] = "";
    int64_t bytes_copied;

    if(ctx)
    {
        if( ((client_ctx_t*)ctx)->nzdh_clt_ctx!=NULL)
            nzdh_clt_ctx=((client_ctx_t*)ctx)->nzdh_clt_ctx;
        else
            return;
        handle = ((client_ctx_t*)ctx)->aes_gcm_handle;
    }
    else
    {
        return;
    }


    /* This callback is invoked when there is data to read on bev. */
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    ++total_messages_read;
    total_bytes_read += evbuffer_get_length(input);
    size_in = evbuffer_get_length(input);

    {
        data_in = new(1, size_in);
        s_memclr(data_in,size_in);
        bytes_copied = evbuffer_remove(input, data_in, size_in);
        if(data_in!=NULL)
        {
            /*mete header date_in->code data_in->leng*/

            remain=size_in;
            while(remain>0)
            {
                int mete_header_len = offsetof(dhpacket_t,data);
                mete_header = new(1,mete_header_len);
                if(data_in==NULL||data_in->len==0)
                    break;
                memcpy(mete_header,data_in, mete_header_len);
#ifdef DEBUG
                printf("[%s:%d:%s]pid(%d)totle package from server, size_in=%d,bytes_copied=%d,mete_header->code=%d,mete_header->len=%d\n",
                       __FILE__,__LINE__,__func__,getpid(),size_in,bytes_copied,(int)mete_header->code,(int)mete_header->len);
                sprintf(errmsg, ">[%s:%d:%s] pid(%d)totle package from server",__FILE__,__LINE__,__func__, getpid());

#endif
                data_used = new(1, mete_header->len);
                s_memclr(data_used,mete_header->len);
                memcpy(data_used,data_in,mete_header->len);
                data_in=(char*)data_in+data_used->len;

#ifdef DEBUG
                printf("[%s:%d:%s]pid(%d)totle package from server, data_used=%p,remain=%d,bytes_copied=%d,data_used->code=%d\n",
                       __FILE__,__LINE__,__func__,getpid(),data_used,remain,bytes_copied,data_used->code);
#endif
                /*step 1: nzdh_KeyAgreePhase1 include ztca_GenerateKey, ztca_CreatePubKeyCtx and ztca_DHGenPubValue*/
                ztca_AllocData(NULL, &other, (data_used->len+1));
                memcpy(other.data, data_used->data, data_used->len-sizeof(dhpacket_t));
                other.len = data_used->len-sizeof(dhpacket_t);
                remain-=data_used->len;
#ifdef DEBUG
                printf("[%s:%d:%s]ackage from server, data_used=%p,remain=%d,bytes_copied=%d,data_used->code=%d\n",
                       __FILE__,__LINE__,__func__,data_used,remain,bytes_copied,data_used->code);
                sprintf(errmsg, ">[%s:%d:%s] pid(%d)totle package from server",__FILE__,__LINE__,__func__, getpid());
                try_continue(1,0);
                _gp_dumpBuf(0, errmsg, (char*)data_used, data_used->len);
                try_continue(0,1);
#endif
                switch((int)data_used->code)
                {
                    case MSG_KEX_DH_GEX_GROUP:   /* the first package of servre, store public key to other structure*/
                    {
#ifdef DEBUG
                        sprintf(errmsg, "<[%s:%d:%s]MSG_KEX_DH_GEX_GROUP pid(%d)Pubkey from server, total len=%d,package len=%d, bytes_copied=%d",
                                __FILE__,__LINE__,__func__, getpid(),size_in, other.len,bytes_copied);
                        try_continue(1,0);
                        _gp_dumpBuf(0, errmsg, other.data, other.len);
                        try_continue(0,1);
#endif
                        agreedSecretLenr = 0;
                        if ((agreedSecretr =
                                 nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLenr)) == NULL)
                        {
                            break;
                        }
                        /*printf("[%s:%d],nzdh_clt_ctx->cryptoCtx = %p, nzdh_clt_ctx=%p\n",__FILE__,__LINE__,nzdh_clt_ctx->cryptoCtx,nzdh_clt_ctx);
                        */err = nzdh_KeyAgreePhase2(ksize, nzdh_clt_ctx->cryptoCtx,other,agreedSecretr,
                                                    (unsigned int*)&agreedSecretLenr,nzdh_clt_ctx);
                        {
                            spacetozero      = agreedSecretLenr;
                            agreedSecretLenr = agreedSecretLenr / 2;
                            agreedSecrets    = agreedSecretr + agreedSecretLenr;
                            agreedSecretLens = agreedSecretLenr;
                            if(handle==NULL)
                            {
                                handle= new(1, sizeof(struct aesgcm_handle_t));
                            }
                            s_memclr(handle, sizeof(struct aesgcm_handle_t));
                            ((client_ctx_t*)ctx)->aes_gcm_handle = handle;

#ifdef DEBUG
                            sprintf(errmsg, ">[%s:%d:%s] pid(%d)AgreeSecrets with client",__FILE__,__LINE__,__func__, getpid());
                            try_continue(1,0);
                            _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
                            try_continue(0,1);
                            sprintf(errmsg, ">[%s:%d:%s] pid(%d)AgreeSecretr with client",__FILE__,__LINE__,__func__, getpid());
                            try_continue(1,0);
                            _gp_dumpBuf(0, errmsg, agreedSecretr, agreedSecretLenr);
                            try_continue(0,1);
                            sprintf(errmsg, "nzdh_KeyAgreePhase2 agreedSecret size %d", agreedSecretLens);
#endif


                            _sess_setupCtx(handle, agreedSecrets, agreedSecretLens,agreedSecretr, agreedSecretLenr,FD_ATTR_RESPONDER);
#ifdef DEBUG
                            sprintf(errmsg, ">[%s:%d:%s] pid(%d)AgreeSecret with client",__FILE__,__LINE__,__func__, getpid());
                            try_continue(1,0);
                            _gp_dumpBuf(0, "AES256 sendKey", handle->sendAesKey, 32);
                            try_continue(0,1);

                            try_continue(1,0);
                            _gp_dumpBuf(0, "AES256 recvKey", handle->recvAesKey, 32);
                            try_continue(0,1);
                            sprintf(errmsg, "After _sess_setupCtx() sendAesKey/recvAesKey size 32");
                            TZTCA_PRN_STAT(errmsg, err);
#endif
                        }

                        evbuffer_lock(output);
                        send_pkg = new(1, sizeof(dhpacket_t));
                        s_memclr(send_pkg, sizeof(dhpacket_t));
                        send_pkg->code = MSG_KEX_DH_GEX_GROUP_ACK;
                        send_pkg->len = sizeof(dhpacket_t);
                        output = bufferevent_get_output(bev);
                        if(output!=NULL)
                        {
                            evbuffer_add(output, send_pkg, send_pkg->len);
                            if(send_pkg!=NULL)
                            {
                                delete(send_pkg,send_pkg->len);
                                send_pkg=NULL;
                            }

                            if(evbuffer_get_length(output)>0)
                            {
                                //bufferevent_write_buffer(bev, output);
                                ;
                            }
                        }
                        evbuffer_unlock(output);
                        /*
                           bufferevent_write(bev, send_pkg, send_pkg->len);
                        */
                        break;
                    }
                    case MSG_KEX_DH_GEX_REPLY:  /* the second package of servre */
                    {
                        /* verify remoter agreed key and send final msg */
                        ++total_connect_num;
#ifdef DEBUG
                        sprintf(errmsg, "<[%s:%d:%s] pid(%d)AgreeSecret from server ",__FILE__,__LINE__,__func__, getpid());
                        try_continue(1,0);
                        _gp_dumpBuf(0, errmsg, other.data, other.len);
                        try_continue(0,1);
                        sprintf(errmsg, ">[%s:%d:%s] pid(%d)AgreeSecret with client",__FILE__,__LINE__,__func__, getpid());
                        try_continue(1,0);
                        _gp_dumpBuf(0, errmsg, nzdh_clt_ctx->agreedSecret, nzdh_clt_ctx->agreedSecretLen);
                        try_continue(0,1);

                        try_continue(1,0);
                        _gp_dumpBuf(0, "AES256 sendKey", handle->sendAesKey, 32);
                        try_continue(0,1);

                        try_continue(1,0);
                        _gp_dumpBuf(0, "AES256 recvKey", handle->recvAesKey, 32);
                        try_continue(0,1);

                        printf("[%s:%d],nzdh_clt_ctx->cryptoCtx = %p, nzdh_clt_ctx=%p\n",__FILE__,__LINE__,nzdh_clt_ctx->cryptoCtx,nzdh_clt_ctx);
#endif
                        if(memcmp(other.data, handle->sendAesKey, 32)!=0
                           || memcmp(((char*)other.data)+32, handle->recvAesKey, 32)!=0)
                        {
                            char sec_msg[] = "Fail";
                            send_pkg = new(1, sizeof(dhpacket_t)+strlen(sec_msg));
                            s_memclr(send_pkg, sizeof(dhpacket_t)+strlen(sec_msg));
                            send_pkg->code = MSG_KEX_DH_GEX_INTERIM;
                            send_pkg->len=sizeof(dhpacket_t)+strlen(sec_msg);
                            memcpy(send_pkg->data,sec_msg,strlen(sec_msg));
                            ++total_failed_num;
                            printf("Failed in compare agreeSecret between client and server\n");
                        }
                        else
                        {
                            char sec_msg[] = "Succ";
                            send_pkg = new(1, sizeof(dhpacket_t)+strlen(sec_msg));
                            s_memclr(send_pkg, sizeof(dhpacket_t)+strlen(sec_msg));
                            send_pkg->code = MSG_KEX_DH_GEX_INTERIM;
                            send_pkg->len=sizeof(dhpacket_t)+strlen(sec_msg);
                            memcpy(send_pkg->data,sec_msg,strlen(sec_msg));
                            ++total_success_num;

                            printf("Succed in compare agreeSecret between client and server\n");

                        }
#ifdef DEBUG
                        printf(">[%s:%d:%s] pid(%d)Succed in compare agreeSecret between client and server,send_pkg->len=%d\n",
                               __FILE__,__LINE__,__func__, getpid(),send_pkg->len);
#endif
                        evbuffer_lock(output);
                        if(output!=NULL)
                        {
                            evbuffer_add(output, send_pkg, send_pkg->len);
                            if(send_pkg!=NULL)
                            {
                                delete(send_pkg,send_pkg->len);
                                send_pkg=NULL;
                            }
                            if(evbuffer_get_length(output)>0)
                            {
                                //bufferevent_write_buffer(bev, output);
                                ;
                            }
                        }
                        evbuffer_unlock(output);
                        /*
                                                bufferevent_write(bev, send_pkg, send_pkg->len);
                        */
                        break;
                    }
                    default:
                        break;
                }
            }
        }

    }

    /* Copy all the data from the input buffer to the output buffer. */
    bufferevent_write_buffer(bev, output);
    //evbuffer_add_buffer(output, input);
}

static void eventcb(struct bufferevent *bev, short events, void *ptr)
{
    if (events & BEV_EVENT_CONNECTED)
    {
        evutil_socket_t fd = bufferevent_getfd(bev);
        set_tcp_no_delay(fd);
    }
    else if (events & BEV_EVENT_ERROR)
    {
        printf("NOT Connected\n");
    }
}

int main(int argc, char **argv)
{
    struct event_base *base;
    struct bufferevent **bevs;
    struct sockaddr_in sin;
    struct event *evtimeout;
    struct timeval timeout;
    int i;
    client_ctx_t **client_ctxs = NULL; /* client ctx store with session */
    client_ctx_t *client_ctx = NULL;
    GPE_DH_CONTEXT_T *nzdh_clt_ctx = NULL;
    zterr err;

    if (argc != 6)
    {
        fprintf(stderr, "Usage: client <addr> <port> <blocksize> ");
        fprintf(stderr, "<sessions> <time>\n");
        return 1;
    }
    char *addr = argv[1];
    int port = atoi(argv[2]);
    int block_size = atoi(argv[3]);
    int session_count = atoi(argv[4]);
    int seconds = atoi(argv[5]);
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;

    base = event_base_new();
    if (!base)
    {
        puts("Couldn't open event base");
        return 1;
    }

    char* message = malloc(block_size);
    for (i = 0; i < block_size; ++i)
    {
        message[i] = i % 128;
    }

    evtimeout = evtimer_new(base, timeoutcb, base);
    evtimer_add(evtimeout, &timeout);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
#if 0
    sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
#endif
    sin.sin_addr.s_addr = inet_addr(addr);
    sin.sin_port = htons(port);

    bevs = malloc(session_count * sizeof(struct bufferevent *));
    client_ctxs = malloc(session_count * sizeof(client_ctx_t));
    for (i = 0; i < session_count; ++i)
    {
        struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        struct evbuffer *output = bufferevent_get_output(bev);
        client_ctx = malloc(sizeof(client_ctx_t));

        if(output==NULL) continue;
        err = generate_clt_pubkey(&nzdh_clt_ctx);

        s_memclr(client_ctx, sizeof(client_ctx_t));
        client_ctx->nzdh_clt_ctx = nzdh_clt_ctx;

        int conver_size = 0;
        dhpacket_t *p = new(1,sizeof(dhpacket_t)+nzdh_clt_ctx->publicValueLen);
        if(!p)
            break;
        p->code = MSG_KEX_DH_GEX_INIT; /* the first package */
        p->len = sizeof(dhpacket_t)+nzdh_clt_ctx->publicValueLen;
        memcpy(p->data, nzdh_clt_ctx->publicValue, nzdh_clt_ctx->publicValueLen);

        bufferevent_setcb(bev, readcb, NULL, eventcb, client_ctx);
        bufferevent_enable(bev, EV_READ|EV_WRITE);
        //evbuffer_add(bufferevent_get_output(bev), message, block_size);
        evbuffer_add(output, p, p->len);
        delete(p, sizeof(dhpacket_t)+nzdh_clt_ctx->publicValueLen);

        if (bufferevent_socket_connect(bev,
                                       (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            /* Error starting connection */
            bufferevent_free(bev);
            if(nzdh_clt_ctx!=NULL)
            {
                nzdh_destroy_1(nzdh_clt_ctx->cryptoCtx);
                free(nzdh_clt_ctx);
                nzdh_clt_ctx=NULL;
            }
            if(client_ctx!=NULL)
            {
                free(client_ctx);
                client_ctx=NULL;

            }
            puts("error connect");
            return -1;
        }
        bevs[i] = bev;
        client_ctxs[i]= client_ctx;
    }

    event_base_dispatch(base);

    for (i = 0; i < session_count; ++i)
    {
        if(client_ctxs[i]!=NULL)
        {
            if(client_ctxs[i]->nzdh_clt_ctx!=NULL)
            {
                nzdh_destroy_1(client_ctxs[i]->nzdh_clt_ctx->cryptoCtx);
                free(client_ctxs[i]->nzdh_clt_ctx);
                client_ctxs[i]->nzdh_clt_ctx=NULL;
            }
            free(client_ctxs[i]);
            client_ctxs[i]=NULL;

        }
        bufferevent_free(bevs[i]);
    }
    free(bevs);
    event_free(evtimeout);
    event_base_free(base);
    free(message);

    printf("%zd total bytes read\n", total_bytes_read);
    printf("%zd total messages read\n", total_messages_read);
    printf("%.3f average messages size\n",
           (double)total_bytes_read / total_messages_read);
    printf("%.3f MiB/s throughtput\n",
           (double)total_bytes_read / (timeout.tv_sec * 1024 * 1024));
    return 0;
}


