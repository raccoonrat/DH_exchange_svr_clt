/**
 * Multithreaded, libevent 2.x-based socket server.
 * Copyright (c) 2012 Qi Huang
 * This software is licensed under the BSD license.
 * See the accompanying LICENSE.txt for details.
 *
 * To compile: ./make
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
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <signal.h>


#include <tux_ztdh.h>
#include <dhsocket.h>
#include <workqueue.h>
#include <tas.h>

/* Port to listen on. */
#define SERVER_PORT 5555
/* Connection backlog (# of backlogged connections to accept). */
#define CONNECTION_BACKLOG 8
/* Number of worker threads.  Should match number of CPU cores reported in
 * /proc/cpuinfo. */
#define NUM_THREADS 2

/* Behaves similarly to fprintf(stderr, ...), but adds file, line, and function
 information. */
#define errorOut(...) {\
    fprintf(stderr, "%s:%d: %s():\t", __FILE__, __LINE__, __FUNCTION__);\
    fprintf(stderr, __VA_ARGS__);\
}

/**
 * Struct to carry around connection (client)-specific data.
 */
typedef struct client {
    /* The client's socket. */
    int fd;

    /* The event_base for this client. */
    //    struct event_base *evbase;

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

static void closeClient(client_t *client) {
    if (client != NULL) {
        if (client->fd >= 0) {
            close(client->fd);
            client->fd = -1;
        }
    }
}

static void closeAndFreeClient(client_t *client) {
    if (client != NULL) {
        closeClient(client);
        if (client->buf_ev != NULL) {
            bufferevent_free(client->buf_ev);
            client->buf_ev = NULL;
        }
        /*
        if (client->evbase != NULL) {
            event_base_free(client->evbase);
            client->evbase = NULL;
        }
        */
        if (client->output_buffer != NULL) {
            evbuffer_free(client->output_buffer);
            client->output_buffer = NULL;
        }
        free(client);
    }
}

static void server_job_function(struct job *job) {
    client_t *client = (client_t *)job->user_data;

    char *data_in; /* recv data buffer */
    int size_in=0;   /* total recv length */
    char cltpubkey[4096];
    int cltpubkey_len;

    zterr err;
    int i;
    unsigned int ksize = sizeof(dhParamsBER128);

    byte minP[5];
    byte iP[5];
    byte maxP[5];
    unsigned int uminP = 0;
    unsigned int uiP = 0;
    unsigned int umaxP = 0;
    unsigned int resP = 0;
    unsigned int tresP = 0;
    int          remain, saved_len;

    GPE_DH_CONTEXT_T *nzdh_svr_ctx = NULL;
    unsigned char    *agreedSecrets = NULL; /* Agreed key */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    ztcaData          remote_data;
    char              msg[32];
    char              errmsg[215] = "";
    dhpacket_t        *data_used = NULL;
    int64_t           bytes_copied;

    dhpacket_t *recv_pkg = NULL;
    struct evbuffer *input = bufferevent_get_input(client->buf_ev);
    struct evbuffer *output = bufferevent_get_output(client->buf_ev);

    err = ztca_Init(FALSE);
    if (err != ZTERR_OK) {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        err |=TZTCA_ERR_INIT;
        return;
    }
    s_memclr(&remote_data, sizeof(ztcaData));

    for(;;) {
		if(input==NULL) break;
        size_in = evbuffer_get_length(input);
		if(size_in<=0)
			break;
        data_in = new(1, size_in);
#ifdef DEBUG
		event_base_dump_events(evbase_accept,stdout);
#endif
        bytes_copied = evbuffer_remove(input, data_in, size_in);
        /*datalen =  bufferevent_read(client->buf_ev, data, sizeof(data));*/
        if(bytes_copied <= 0) {
            break;
        }
        {

#ifdef DEBUG
            printf("[%s:%d:%s]cltpubkey_len of recv pkg =%d, totle len=%d\n",
                   __FILE__,__LINE__,__func__,bytes_copied, size_in);
            try_continue(1,0);
            _gp_dumpBuf(0, errmsg, data_in, bytes_copied);
            try_continue(0,1);
#endif
        }

        remain = bytes_copied;
        data_used = data_in;
        for(;;) {
            if(remain<=0||data_used==NULL||data_used->len<8||data_used->len >size_in) {
                delete(data_in, size_in);
                break;
            }

            recv_pkg = new(1,remain);
            memcpy(recv_pkg, data_used, remain);
#ifdef DEBUG
            printf("[%s:%d:%s]recv_pkg->code=%d,recv_pkg->len=%d\n",
                   __FILE__,__LINE__,__func__,recv_pkg->code,recv_pkg->len);
#endif
            switch(recv_pkg->code) {
                case MSG_KEX_DH_GEX_INIT:  /* the first client package */
                    cltpubkey_len = recv_pkg->len - sizeof(dhpacket_t);
                    memcpy(cltpubkey,recv_pkg->data,cltpubkey_len);

#ifdef DEBUG
                    printf("[%s:%d:%s]MSG_KEX_DH_GEX_INIT cltpubkey_len of recv pkg =%d, remain=%d\n",
                           __FILE__,__LINE__,__func__,cltpubkey_len,remain);
                    sprintf(errmsg, "<[%s:%d:%s] pid(%d) Pubkey from client",
                            __FILE__,__LINE__,__func__,getpid());
                    try_continue(1,0);
                    _gp_dumpBuf(0, errmsg, cltpubkey, cltpubkey_len);
                    try_continue(0,1);
#endif

                    /* start TUX DH exchange key protocol*/
                    {
                        /*step1: svr generateParameters, send svr pub to client as reply*/
                        err = nzdh_KeyAgreePhase1(ksize,(GPE_DH_CONTEXT_T**)&nzdh_svr_ctx);
                        {
                            dhpacket_t *send_pkg = new(1,sizeof(dhpacket_t)+nzdh_svr_ctx->publicValueLen);

                            if(!send_pkg)
                                return;

                            s_memclr(send_pkg, sizeof(dhpacket_t)+nzdh_svr_ctx->publicValueLen);
                            send_pkg->code = MSG_KEX_DH_GEX_GROUP;    /* the first package of server */
                            send_pkg->len = nzdh_svr_ctx->publicValueLen+sizeof(dhpacket_t);

                            memcpy(send_pkg->data,nzdh_svr_ctx->publicValue,nzdh_svr_ctx->publicValueLen);
							if(client!=NULL && output!=NULL) {
								evbuffer_add(output, send_pkg, send_pkg->len);
								if(evbuffer_get_length(output)>0){
	                            	bufferevent_write_buffer(client->buf_ev, output);
								}
							}
#ifdef DEBUG
                            sprintf(errmsg, ">[%s:%d:%s] pid(%d) Pubkey with server", __FILE__,__LINE__,__func__,getpid());
                            try_continue(1,0);
                            _gp_dumpBuf(0, errmsg, send_pkg, send_pkg->len);
                            try_continue(0,1);
#endif
                            delete(send_pkg, sizeof(dhpacket_t)+nzdh_svr_ctx->publicValueLen);
                        }
#ifdef DEBUG
                        sprintf(msg, "nzdh_KeyAgreePhase1 key size %d", ksize);
                        TZTCA_PRN_STAT(msg, err);
#endif
                    }
                    {
                        /*step2: recv client pubkey create agreedSecret in server side*/

                        ztca_AllocData(NULL, &remote_data, (cltpubkey_len+1));
                        memcpy(remote_data.data, cltpubkey, cltpubkey_len);
                        remote_data.len = cltpubkey_len;
                        agreedSecretLens = 0;
                        if ((agreedSecrets =
                                 nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLens)) == NULL) {
                            break;
                        }

                        err = nzdh_KeyAgreePhase2(ksize, nzdh_svr_ctx->cryptoCtx,remote_data,agreedSecrets,
                                                  (unsigned int*)&agreedSecretLens,nzdh_svr_ctx);

                        {
                            dhpacket_t *send_pkg = new(1,sizeof(dhpacket_t)+agreedSecretLens);
                            if(!send_pkg)
                                break;
                            s_memclr(send_pkg, sizeof(dhpacket_t)+agreedSecretLens);
                            send_pkg->code = MSG_KEX_DH_GEX_REPLY;  /* the second package of server */
                            send_pkg->len = agreedSecretLens+sizeof(dhpacket_t);
                            memcpy(send_pkg->data, agreedSecrets, agreedSecretLens);
							if(client!=NULL && output!=NULL) {
								evbuffer_add(output, send_pkg, send_pkg->len);
								if(evbuffer_get_length(output)>0){
	                            	bufferevent_write_buffer(client->buf_ev, output);
								}
							}
#ifdef DEBUG
                            sprintf(msg, "nzdh_KeyAgreePhase2 agreedSecret size %d", agreedSecretLens);
                            sprintf(errmsg, ">[%s:%d:%s] pid(%d) AgreeSecret with server",__FILE__,__LINE__,__func__, getpid());
                            try_continue(1,0);
                            _gp_dumpBuf(0, errmsg, send_pkg, send_pkg->len);
                            try_continue(0,1);
                            TZTCA_PRN_STAT(msg, err);
#endif
                            delete(send_pkg, sizeof(dhpacket_t)+agreedSecretLens);
                        }

                    }
                    break;
                case MSG_KEX_DH_GEX_INTERIM: {
                    byte final_rec[5];

                    memcpy(final_rec, recv_pkg->data,recv_pkg->len-sizeof(recv_pkg->len));
                    final_rec[4] = '\0';
                    if(constantVerify(final_rec, (byte*)"Fail") == 1) {
                        printf("Secret sharing failed\n");
                        try_continue(1,0);
                        sprintf(errmsg, ">[%s:%d:%s] pid(%d) Pubkey with server MSG_KEX_DH_GEX_INTERIM", __FILE__,__LINE__,__func__,getpid());
                        _gp_dumpBuf(0, errmsg, nzdh_svr_ctx->publicValue, nzdh_svr_ctx->publicValueLen);
                        sprintf(errmsg, "<[%s:%d:%s] pid(%d) Pubkey from client",__FILE__,__LINE__,__func__, getpid());
                        _gp_dumpBuf(0, errmsg, remote_data.data, remote_data.len);
                        sprintf(errmsg, ">[%s:%d:%s] pid(%d) AgreeSecret with server",__FILE__,__LINE__,__func__, getpid());
                        _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
                        try_continue(0,1);
                    } else if(constantVerify(final_rec, (byte*)"Succ") == 1) {
#ifdef DEBUG
                        printf("Secret sharing succeeded\n");
#endif
                        /**/
                    } else {
                        printf("Secret sharing failed\n");
                    }
                    break;
                }

                case MSG_KEX_DH_GEX_GROUP_ACK:  /* the first client package */
#ifdef DEBUG
                    printf("get MSG_KEX_DH_GEX_GROUP_ACK\n");
#endif
                    break;
                default:
                    break;
            }

            saved_len = recv_pkg->len;
            data_used = (char*)data_used + recv_pkg->len;
            delete(recv_pkg, remain);
            remain-=saved_len;
        }


        /*this is the orig send
         bufferevent_write(client->buf_ev, cltpubkey, cltpubkey_len);
         */
    }

}

#if 0
static void server_job_function(struct job *job) {
    client_t *client = (client_t *)job->user_data;

    char data[4096];
    int cltpubkey_len;

    for(;;) {
        cltpubkey_len =  bufferevent_read(client->buf_ev, data, sizeof(data));
        if(cltpubkey_len <= 0) {
            break;
        }
        {
#ifdef DEBUG
            char errmsg[215] = "";
            int i = 0;
            printf("[%s:%d:%s]cltpubkey_len of recv pkg =%d, totle len=%d\n",__FILE__,__LINE__,__func__,cltpubkey_len,sizeof(data));
            try_continue(1,0);
            _gp_dumpBuf(0, errmsg, data, cltpubkey_len);
            try_continue(0,1);
            for(i=129; i<150; i++)
                data[i]=i;

#endif
        }
        bufferevent_write(client->buf_ev, data, cltpubkey_len);
    }

}
#endif


/**
 * Called by libevent when there is data to read.
 */
void buffered_on_read(struct bufferevent *bev, void *arg) {
    client_t *client = (client_t *)arg;
    job_t *job;


    /* Create a job object and add it to the work queue. */
    if ((job = malloc(sizeof(*job))) == NULL) {
        warn("failed to allocate memory for job state");
        closeAndFreeClient(client);
        return;
    }
    job->job_function = server_job_function;
    job->user_data = client;

    workqueue_add_job(&workqueue, job);

}

/**
 * Called by libevent when the write buffer reaches 0.  We only
 * provide this because libevent expects it, but we don't use it.
 */
void buffered_on_write(struct bufferevent *bev, void *arg) {
}

/**
 * Called by libevent when there is an error on the underlying socket
 * descriptor.
 */
void buffered_on_error(struct bufferevent *bev, short what, void *arg) {
    struct client *client = (struct client *)arg;

    if (what & EVBUFFER_EOF) {
        /* Client disconnected, remove the read event and the
         * free the client structure. */
#ifdef DEBUG
        printf("Client disconnected.\n");
#endif
    } else {
        printf("Client socket error, disconnecting.\n");
    }
    bufferevent_free(client->buf_ev);
    close(client->fd);
    free(client);
}


/**
 * This function will be called by libevent when there is a connection
 * ready to be accepted.
 */
void on_accept(evutil_socket_t fd, short ev, void *arg) {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    client_t *client;

    client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        warn("accept failed");
        return;
    }

    /* Set the client socket to non-blocking mode. */
    if (evutil_make_socket_nonblocking(client_fd) < 0) {
        warn("failed to set client socket to non-blocking");
        close(client_fd);
        return;
    }

    /* Create a client object. */
    if ((client = malloc(sizeof(*client))) == NULL) {
        warn("failed to allocate memory for client state");
        close(client_fd);
        return;
    }
    memset(client, 0, sizeof(*client));
    client->fd = client_fd;

    /* Add any custom code anywhere from here to the end of this function
     * to initialize your application-specific attributes in the client struct.
     */

    if ((client->output_buffer = evbuffer_new()) == NULL) {
        warn("client output buffer allocation failed");
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
    client->buf_ev = bufferevent_socket_new(evbase_accept, client_fd,
                                            BEV_OPT_CLOSE_ON_FREE);
    if ((client->buf_ev) == NULL) {
        warn("client bufferevent creation failed");
        closeAndFreeClient(client);
        return;
    }
    bufferevent_setcb(client->buf_ev, buffered_on_read, buffered_on_write,
                      buffered_on_error, client);

    /* We have to enable it before our callbacks will be
     * called. */
    bufferevent_enable(client->buf_ev, EV_READ );
#ifdef DEBUG
    printf("Accepted connection from %s\n",
           inet_ntoa(client_addr.sin_addr));
#endif
}

/**
 * Run the server.  This function blocks, only returning when the server has
 * terminated.
 */
int runServer(void) {
    evutil_socket_t listenfd;
    struct sockaddr_in listen_addr;
    struct event *ev_accept;
    int reuseaddr_on;

    /* Set signal handlers */
    sigset_t sigset;
    sigemptyset(&sigset);
    struct sigaction siginfo = {
        .sa_handler = sighandler,
        .sa_mask = sigset,
        .sa_flags = SA_RESTART,
    };
    sigaction(SIGINT, &siginfo, NULL);
    sigaction(SIGTERM, &siginfo, NULL);

    /* Create our listening socket. */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        err(1, "listen failed");
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(SERVER_PORT);
    if (bind(listenfd, (struct sockaddr *)&listen_addr, sizeof(listen_addr))
        < 0) {
        err(1, "bind failed");
    }
    if (listen(listenfd, CONNECTION_BACKLOG) < 0) {
        err(1, "listen failed");
    }
    reuseaddr_on = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
               sizeof(reuseaddr_on));

    /* Set the socket to non-blocking, this is essential in event
     * based programming with libevent. */
    if (evutil_make_socket_nonblocking(listenfd) < 0) {
        err(1, "failed to set server socket to non-blocking");
    }

	event_enable_debug_mode();


    if ((evbase_accept = event_base_new()) == NULL) {
        perror("Unable to create socket accept event base");
        close(listenfd);
        return 1;
    }

    /* Initialize work queue. */
    if (workqueue_init(&workqueue, NUM_THREADS)) {
        perror("Failed to create work queue");
        close(listenfd);
        workqueue_shutdown(&workqueue);
        return 1;
    }

    /* We now have a listening socket, we create a read event to
     * be notified when a client connects. */
    ev_accept = event_new(evbase_accept, listenfd, EV_READ|EV_PERSIST,
                          on_accept, (void *)&workqueue);
    event_add(ev_accept, NULL);

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
 * Kill the server.  This function can be called from another thread to kill
 * the server, causing runServer() to return.
 */
void killServer(void) {
    fprintf(stdout, "Stopping socket listener event loop.\n");
    if (event_base_loopexit(evbase_accept, NULL)) {
        perror("Error shutting down server");
    }
    fprintf(stdout, "Stopping workers.\n");
    workqueue_shutdown(&workqueue);
}

static void sighandler(int signal) {
    fprintf(stdout, "Received signal %d: %s.  Shutting down.\n", signal,
            strsignal(signal));
    killServer();
}

/* Main function for demonstrating the echo server.
 * You can remove this and simply call runServer() from your application. */
int main(int argc, char *argv[]) {
    return runServer();
}
