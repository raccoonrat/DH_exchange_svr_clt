/**
 * Multithreaded, libevent-based socket server.
 * Copyright (c) 2012 Ronald Bennett Cemer
 * This software is licensed under the BSD license.
 * See the accompanying LICENSE.txt for details.
 *
 * To compile: gcc -o echoserver_threaded echoserver_threaded.c workqueue.c -levent -lpthread
 * To run: ./echoserver_threaded
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <event.h>
#include <signal.h>

#include "workqueue.h"

#include <tux_ztdh.h>
#include <dhsocket.h>
#include <workqueue.h>
#include <tas.h>

/* Port to listen on. */
#define SERVER_PORT 5555
/* Connection backlog (# of backlogged connections to accept). */
#define CONNECTION_BACKLOG 8
/* Socket read and write timeouts, in seconds. */
#define SOCKET_READ_TIMEOUT_SECONDS 10
#define SOCKET_WRITE_TIMEOUT_SECONDS 10
/* Number of worker threads.  Should match number of CPU cores reported in /proc/cpuinfo. */
#define NUM_THREADS 100

/* Behaves similarly to fprintf(stderr, ...), but adds file, line, and function
 information. */
#define errorOut(...) {\
    fprintf(stderr, "%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__);\
    fprintf(stderr, __VA_ARGS__);\
}

/**
 * Struct to carry around connection (client)-specific data.
 */
typedef struct client
{
    /* The client's socket. */
    int fd;

    /* The event_base for this client. */
    struct event_base *evbase;

    /* The bufferedevent for this client. */
    struct bufferevent *buf_ev;

    /* The output buffer for this client. */
    struct evbuffer *output_buffer;

    /* Here you can add your own application-specific attributes which
     * are connection-specific. */
} client_t;

static struct event_base *evbase_accept;
static workqueue_t workqueue;

/* Signal handler function (defined below). */
static void sighandler(int signal);

/**
 * Set a socket to non-blocking mode.
 */
static int setnonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags < 0) return flags;
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0) return -1;
    return 0;
}

static void closeClient(client_t *client)
{
    if (client != NULL)
    {
        if (client->fd >= 0)
        {
            close(client->fd);
            client->fd = -1;
        }
    }
}

static void closeAndFreeClient(client_t *client)
{
    if (client != NULL)
    {
        closeClient(client);
        if (client->buf_ev != NULL)
        {
            bufferevent_free(client->buf_ev);
            client->buf_ev = NULL;
        }
        if (client->evbase != NULL)
        {
            event_base_free(client->evbase);
            client->evbase = NULL;
        }
        if (client->output_buffer != NULL)
        {
            evbuffer_free(client->output_buffer);
            client->output_buffer = NULL;
        }
        free(client);
    }
}


/**
 * Called by libevent when there is data to read.
 */
void buffered_on_read(struct bufferevent *bev, void *arg)
{
    client_t *client = (client_t *)arg;
    char data[4096];
    int nbytes;
    int64_t           bytes_copied;
    char              errmsg[215] = "";

    zterr err;
    dhpacket_t *recv_pkg = NULL;
    dhpacket_t *send_pkg = NULL;
    char cltpubkey[4096];
    int cltpubkey_len;
    GPE_DH_CONTEXT_T *nzdh_svr_ctx = NULL;
    unsigned int ksize = sizeof(dhParamsBER128);
    ztcaData          remote_data;
    unsigned char    *agreedSecrets = NULL; /* Agreed key SEND*/
    unsigned char    *agreedSecretr = NULL; /* Agreed key receive */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    unsigned int      agreedSecretLenr; /* The length of the pn */
    unsigned int      spacetozero = 0;  /* Length of space to NULL */
    AES_GCM_HANDLE_P_T handle=NULL;

    struct evbuffer *input = bufferevent_get_input(client->buf_ev);
    struct evbuffer *output = client->output_buffer;

    evbuffer_enable_locking(input,NULL);
    evbuffer_enable_locking(output,NULL);

    memset(&remote_data, 0, sizeof(ztcaData));

    err = ztca_Init(FALSE);
    if (err != ZTERR_OK)
    {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        err |=TZTCA_ERR_INIT;
        return;
    }


    /* Copy the data from the input buffer to the output buffer in 4096-byte chunks.
     * There is a one-liner to do the whole thing in one shot, but the purpose of this server
     * is to show actual real-world reading and writing of the input and output buffers,
     * so we won't take that shortcut here. */
    while ((nbytes = EVBUFFER_LENGTH(bev->input)) > 0)
    {
        /* Remove a chunk of data from the input buffer, copying it into our local array (data). */
        if (nbytes > 4096) nbytes = 4096;
        bytes_copied = evbuffer_remove(bev->input, data, nbytes);

#ifdef DEBUG
        printf("[%s:%d:%s]cltpubkey_len of recv pkg =%d, totle len=%d\n",
               __FILE__,__LINE__,__func__,bytes_copied, nbytes);
        evbuffer_lock(input);
        _gp_dumpBuf(0, errmsg, (char*)data, bytes_copied);
        evbuffer_unlock(input);
#endif
        recv_pkg = new(1,bytes_copied);
        memcpy(recv_pkg, data, bytes_copied);

#ifdef DEBUG
        printf("[%s:%d:%s]recv_pkg->code=%d,recv_pkg->len=%d\n",
               __FILE__,__LINE__,__func__,recv_pkg->code,recv_pkg->len);
#endif
        switch(recv_pkg->code)
        {
            case MSG_KEX_DH_GEX_INIT:  /* the first client package */
                cltpubkey_len = recv_pkg->len - sizeof(dhpacket_t);
                memcpy(cltpubkey,recv_pkg->data,cltpubkey_len);
                if(nzdh_svr_ctx!=NULL)
                {
                    nzdh_destroy_1(nzdh_svr_ctx->cryptoCtx);
                    free(nzdh_svr_ctx);
                    nzdh_svr_ctx=NULL;
                }
#ifdef DEBUG
                printf("[%s:%d:%s]MSG_KEX_DH_GEX_INIT cltpubkey_len of recv pkg =%d, remain=%d\n",
                       __FILE__,__LINE__,__func__,cltpubkey_len,bytes_copied);
                sprintf(errmsg, "<[%s:%d:%s] pid(%d) Pubkey from client",
                        __FILE__,__LINE__,__func__,getpid());
                evbuffer_lock(input);
                _gp_dumpBuf(0, errmsg, cltpubkey, cltpubkey_len);
                evbuffer_unlock(input);
#endif
                /* start TUX DH exchange key protocol*/
                {
                    /*step1: svr generateParameters, send svr pub to client as reply*/
                    err = nzdh_KeyAgreePhase1(ksize,(GPE_DH_CONTEXT_T**)&nzdh_svr_ctx);
                    send_pkg = new(1,sizeof(dhpacket_t)+nzdh_svr_ctx->publicValueLen);
                    if(!send_pkg)
                        return;
                    s_memclr(send_pkg, sizeof(dhpacket_t)+nzdh_svr_ctx->publicValueLen);
                    send_pkg->code = MSG_KEX_DH_GEX_GROUP;    /* the first package of server */
                    send_pkg->len = nzdh_svr_ctx->publicValueLen+sizeof(dhpacket_t);
                    memcpy(send_pkg->data,nzdh_svr_ctx->publicValue,nzdh_svr_ctx->publicValueLen);
#ifdef DEBUG
                    printf("[%s:%d]client=%p,client->buf_ev=%p,output=%p\n",__FILE__,__LINE__,client,client->buf_ev,output);

                    sprintf(errmsg, ">[%s:%d:%s] pid(%d) Pubkey with server", __FILE__,__LINE__,__func__,getpid());
                    evbuffer_lock(input);
                    _gp_dumpBuf(0, errmsg, send_pkg, send_pkg->len);
                    evbuffer_unlock(input);
                    sprintf(errmsg, "nzdh_KeyAgreePhase1 key size %d", ksize);
                    TZTCA_PRN_STAT(errmsg, err);
#endif
                    /* Add the chunk of data from our local array (data) to the client's output buffer. */
                    if(send_pkg != NULL && send_pkg->len>0)
                    {

                        evbuffer_add(client->output_buffer, send_pkg, send_pkg->len);
                        if(send_pkg!=NULL)
                        {
                            delete(send_pkg, send_pkg->len);
                            send_pkg = NULL;
                        }
                    }
                    else
                    {
                        evbuffer_add(client->output_buffer, data, nbytes);
                    }
                    /*step2: recv client pubkey create agreedSecret in server side*/
                    ztca_AllocData(NULL, &remote_data, (cltpubkey_len+1));
                    memcpy(remote_data.data, cltpubkey, cltpubkey_len);
                    remote_data.len = cltpubkey_len;
                    agreedSecretLenr = 0;
                    if ((agreedSecretr =
                             nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLenr)) == NULL)
                    {
                        break;
                    }

                    err = nzdh_KeyAgreePhase2(ksize, nzdh_svr_ctx->cryptoCtx,remote_data,agreedSecretr,
                                              (unsigned int*)&agreedSecretLenr,nzdh_svr_ctx);
                    /* filling sendkey and recvkey */
                    {
                        spacetozero      = agreedSecretLenr;
                        agreedSecretLenr = agreedSecretLenr / 2;
                        agreedSecrets    = agreedSecretr + agreedSecretLenr;
                        agreedSecretLens = agreedSecretLenr;
#ifdef DEBUG
                        sprintf(errmsg, ">[%s:%d:%s] pid(%d)nzdh_KeyAgreePhase2 agreedSecrets with server size %d",__FILE__,__LINE__,__func__, getpid(),agreedSecretLens);
                        evbuffer_lock(input);
                        _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
                        evbuffer_unlock(input);
                        sprintf(errmsg, ">[%s:%d:%s] pid(%d) agreedSecretr with server",__FILE__,__LINE__,__func__, getpid());
                        evbuffer_lock(input);
                        _gp_dumpBuf(0, errmsg, agreedSecretr, agreedSecretLenr);
                        evbuffer_unlock(input);
#endif
                        if(handle==NULL)
                        {
                            handle= new(1, sizeof(struct aesgcm_handle_t));
                        }

                        s_memclr(handle, sizeof(struct aesgcm_handle_t));

                        nzdh_destroy_1(nzdh_svr_ctx->cryptoCtx);

                        (void)memset((char *)nzdh_svr_ctx, 0, sizeof(GPE_DH_CONTEXT_T));
                        free(nzdh_svr_ctx);
                        _sess_setupCtx(handle, agreedSecrets, agreedSecretLens,agreedSecretr, agreedSecretLenr,FD_ATTR_RESPONDER);

#ifdef DEBUG
                        evbuffer_lock(input);
                        sprintf(errmsg, "[%s:%d:%s] pid(%d) agreedSecretr with server AES256 sendKey",__FILE__,__LINE__,__func__, getpid());
                        _gp_dumpBuf(0, errmsg, handle->sendAesKey, 32);
                        evbuffer_unlock(input);

                        evbuffer_lock(input);
                        sprintf(errmsg, "[%s:%d:%s] pid(%d) agreedSecretr with server AES256 recvKey",__FILE__,__LINE__,__func__, getpid());
                        _gp_dumpBuf(0, errmsg, handle->recvAesKey, 32);
                        evbuffer_unlock(input);
#endif
                        {
                            int send_len=32+32;
                            send_pkg = new(1,sizeof(dhpacket_t)+send_len);
                            if(!send_pkg)
                                break;
                            s_memclr(send_pkg, sizeof(dhpacket_t)+send_len);
                            send_pkg->code = MSG_KEX_DH_GEX_REPLY;  /* the second package of server */
                            send_pkg->len = send_len+sizeof(dhpacket_t);
                            memcpy(send_pkg->data, handle->sendAesKey, 32);
                            memcpy(send_pkg->data+32, handle->recvAesKey, 32);
                            /* Add the chunk of data from our local array (data) to the client's output buffer. */
                            if(send_pkg != NULL && send_pkg->len>0)
                            {
                                evbuffer_add(client->output_buffer, send_pkg, send_pkg->len);
                            }
                            else
                            {
                                evbuffer_add(client->output_buffer, data, nbytes);
                            }

#ifdef DEBUG
                            sprintf(errmsg, ">[%s:%d:%s] pid(%d) AgreeSecret with server, agreedSecret size %d",__FILE__,__LINE__,__func__, getpid(),agreedSecretLens);
                            evbuffer_lock(input);
                            _gp_dumpBuf(0, errmsg, send_pkg, send_pkg->len);
                            evbuffer_unlock(input);
                            TZTCA_PRN_STAT(errmsg, err);
#endif
                            if(send_pkg!=NULL)
                            {
                                delete(send_pkg, send_pkg->len);
                                send_pkg=NULL;
                            }
                        }
                    }
                }
                break;
            default:
                break;
        }
        if(send_pkg!=NULL)
        {
            delete(send_pkg, send_pkg->len);
            send_pkg=NULL;
        }
#if 0
        /* Add the chunk of data from our local array (data) to the client's output buffer. */
        if(send_pkg != NULL && send_pkg->len>0)
        {
            printf("[%s:%d]send_pkg%p\n",__FILE__,__LINE__,send_pkg);
            evbuffer_add(client->output_buffer, send_pkg, send_pkg->len);
        }
        else
        {
            evbuffer_add(client->output_buffer, data, nbytes);
        }
#endif
    }

    /* Send the results to the client.  This actually only queues the results for sending.
     * Sending will occur asynchronously, handled by libevent. */
    if (bufferevent_write_buffer(bev, client->output_buffer))
    {
        errorOut("Error sending data to client on fd %d\n", client->fd);
        closeClient(client);
    }

}

/**
 * Called by libevent when the write buffer reaches 0.  We only
 * provide this because libevent expects it, but we don't use it.
 */
void buffered_on_write(struct bufferevent *bev, void *arg)
{
}

/**
 * Called by libevent when there is an error on the underlying socket
 * descriptor.
 */
void buffered_on_error(struct bufferevent *bev, short what, void *arg)
{
    closeClient((client_t *)arg);
}

static void server_job_function(struct job *job)
{
    client_t *client = (client_t *)job->user_data;

    event_base_dispatch(client->evbase);
    closeAndFreeClient(client);
    free(job);
}

/**
 * This function will be called by libevent when there is a connection
 * ready to be accepted.
 */
void on_accept(int fd, short ev, void *arg)
{
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    workqueue_t *workqueue = (workqueue_t *)arg;
    client_t *client;
    job_t *job;

    client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
        warn("accept failed");
        return;
    }

    /* Set the client socket to non-blocking mode. */
    if (setnonblock(client_fd) < 0)
    {
        warn("failed to set client socket to non-blocking");
        close(client_fd);
        return;
    }

    /* Create a client object. */
    if ((client = malloc(sizeof(*client))) == NULL)
    {
        warn("failed to allocate memory for client state");
        close(client_fd);
        return;
    }
    memset(client, 0, sizeof(*client));
    client->fd = client_fd;

    /* Add any custom code anywhere from here to the end of this function
     * to initialize your application-specific attributes in the client struct. */

    if ((client->output_buffer = evbuffer_new()) == NULL)
    {
        warn("client output buffer allocation failed");
        closeAndFreeClient(client);
        return;
    }

    if ((client->evbase = event_base_new()) == NULL)
    {
        warn("client event_base creation failed");
        closeAndFreeClient(client);
        return;
    }

    /* Create the buffered event.
     *
     * The first argument is the file descriptor that will trigger
     * the events, in this case the clients socket.
     *
     * The second argument is the callback that will be called
     * when data has been read from the socket and is available to
     * the application.
     *
     * The third argument is a callback to a function that will be
     * called when the write buffer has reached a low watermark.
     * That usually means that when the write buffer is 0 length,
     * this callback will be called.  It must be defined, but you
     * don't actually have to do anything in this callback.
     *
     * The fourth argument is a callback that will be called when
     * there is a socket error.  This is where you will detect
     * that the client disconnected or other socket errors.
     *
     * The fifth and final argument is to store an argument in
     * that will be passed to the callbacks.  We store the client
     * object here.
     */
    if ((client->buf_ev = bufferevent_new(client_fd, buffered_on_read, buffered_on_write, buffered_on_error, client)) == NULL)
    {
        warn("client bufferevent creation failed");
        closeAndFreeClient(client);
        return;
    }
    bufferevent_base_set(client->evbase, client->buf_ev);

    bufferevent_settimeout(client->buf_ev, SOCKET_READ_TIMEOUT_SECONDS, SOCKET_WRITE_TIMEOUT_SECONDS);

    /* We have to enable it before our callbacks will be
     * called. */
    bufferevent_enable(client->buf_ev, EV_READ);

    /* Create a job object and add it to the work queue. */
    if ((job = malloc(sizeof(*job))) == NULL)
    {
        warn("failed to allocate memory for job state");
        closeAndFreeClient(client);
        return;
    }
    job->job_function = server_job_function;
    job->user_data = client;

    workqueue_add_job(workqueue, job);
}

/**
 * Run the server.  This function blocks, only returning when the server has terminated.
 */
int runServer(void)
{
    int listenfd;
    struct sockaddr_in listen_addr;
    struct event ev_accept;
    int reuseaddr_on;

    /* Initialize libevent. */
    event_init();

    /* Set signal handlers */
    sigset_t sigset;
    sigemptyset(&sigset);
    struct sigaction siginfo =
    {
        .sa_handler = sighandler,
        .sa_mask = sigset,
        .sa_flags = SA_RESTART,
    };
    sigaction(SIGINT, &siginfo, NULL);
    sigaction(SIGTERM, &siginfo, NULL);

    /* Create our listening socket. */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
    {
        err(1, "listen failed");
    }
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(SERVER_PORT);
    if (bind(listenfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
    {
        err(1, "bind failed");
    }
    if (listen(listenfd, CONNECTION_BACKLOG) < 0)
    {
        err(1, "listen failed");
    }
    reuseaddr_on = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, sizeof(reuseaddr_on));

    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (setnonblock(listenfd) < 0)
    {
        err(1, "failed to set server socket to non-blocking");
    }

    if ((evbase_accept = event_base_new()) == NULL)
    {
        perror("Unable to create socket accept event base");
        close(listenfd);
        return 1;
    }

    /* Initialize work queue. */
    if (workqueue_init(&workqueue, NUM_THREADS))
    {
        perror("Failed to create work queue");
        close(listenfd);
        workqueue_shutdown(&workqueue);
        return 1;
    }

    /* We now have a listening socket, we create a read event to
     * be notified when a client connects. */
    event_set(&ev_accept, listenfd, EV_READ|EV_PERSIST, on_accept, (void *)&workqueue);
    event_base_set(evbase_accept, &ev_accept);
    event_add(&ev_accept, NULL);

    printf("Server running.\n");

    /* Start the event loop. */
    event_base_dispatch(evbase_accept);

    event_base_free(evbase_accept);
    evbase_accept = NULL;

    close(listenfd);

    printf("Server shutdown.\n");

    return 0;
}

/**
 * Kill the server.  This function can be called from another thread to kill the
 * server, causing runServer() to return.
 */
void killServer(void)
{
    fprintf(stdout, "Stopping socket listener event loop.\n");
    if (event_base_loopexit(evbase_accept, NULL))
    {
        perror("Error shutting down server");
    }
    fprintf(stdout, "Stopping workers.\n");
    workqueue_shutdown(&workqueue);
}

static void sighandler(int signal)
{
    fprintf(stdout, "Received signal %d: %s.  Shutting down.\n", signal, strsignal(signal));
    killServer();
}

/* Main function for demonstrating the echo server.
 * You can remove this and simply call runServer() from your application. */
int main(int argc, char *argv[])
{
    return runServer();
}

