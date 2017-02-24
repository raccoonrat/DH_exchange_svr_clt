#include <tux_ztdh.h>
#include <dhsocket.h>
#include <dhutils.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <resolv.h>
#include <sys/wait.h>
#include <string.h>
#include <tas.h>
#include <sys/mman.h>

#define MAXCLIENTS  20
int ChildCount=0;
volatile size_t *glob_var;

static inline int count(int x) {
    return floor(log10(x)) + 1;
}

void sig_child() {
    pid_t processID;           /* Process ID from fork() */

    while (ChildCount) { /* Clean up all zombies */
        processID = waitpid((pid_t) -1, NULL, WNOHANG);  /* Non-blocking wait */
        if (processID < 0)  /* waitpid() error? */
            diewitherror("waitpid() failed");
        else if (processID == 0)  /* No child to wait on */
            break;
        else {
            ChildCount--;  /* Cleaned up after a child */

        }
    }
}

void child(dhsocket_t sock) {
    zterr err;
    int stat = 0;
    char *buff;
    int i;
    unsigned int ksize = sizeof(dhParamsBER128);
    int fd;

    byte minP[5];
    byte iP[5];
    byte maxP[5];
    unsigned int uminP = 0;
    unsigned int uiP = 0;
    unsigned int umaxP = 0;
    unsigned int resP = 0;
    unsigned int tresP = 0;
    int   retry_num = 0;

    GPE_DH_CONTEXT_T *nzdh_svr_ctx = NULL;
    unsigned char    *agreedSecrets = NULL; /* Agreed key */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    ztcaData          remote_data;
    char              msg[32];

    try_continue(1,0);
    (*glob_var)++;
    try_continue(0,1);
#ifdef DEBUG
    printf("<pid=%d>glob_var=%d\n",getpid(),*glob_var);
#endif
    if (munmap(glob_var, sizeof(int)) == -1)
        goto err_ret;

    err = ztca_Init(FALSE);
    if (err != ZTERR_OK) {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        err |=TZTCA_ERR_INIT;
        goto err_ret;
    }
    s_memclr(&remote_data, sizeof(ztcaData));

    /* start TUX DH exchange key protocol*/
    {
        /*step1: svr generateParameters, send svr pub to client as reply*/
        int stat = nzdh_KeyAgreePhase1(ksize,(GPE_DH_CONTEXT_T**)&nzdh_svr_ctx);
        {
            char errmsg[215] = "";
            int converted_number = htonl(nzdh_svr_ctx->publicValueLen);
            try_continue(1,0);
            dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_GROUP_SZ, (byte*)&(converted_number), sizeof(converted_number));
            try_continue(0,1);
            try_continue(1,0);
            dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_GROUP, nzdh_svr_ctx->publicValue, nzdh_svr_ctx->publicValueLen);
            try_continue(0,1);
#ifdef DEBUG
            sprintf(errmsg, ">[%s:%d:%s] pid(%d) Pubkey with server", __FILE__,__LINE__,__func__,getpid());
            try_continue(1,0);
            _gp_dumpBuf(0, errmsg, nzdh_svr_ctx->publicValue, nzdh_svr_ctx->publicValueLen);
            try_continue(0,1);
#endif
        }
#ifdef DEBUG
        sprintf(msg, "nzdh_KeyAgreePhase1 key size %d", ksize);
        TZTCA_PRN_STAT(msg, stat);
#endif
    }
    {
        /*step2: recv client pubkey*/
        int ret = 0;
        unsigned int bs = nzdh_svr_ctx->publicValueLen;
        byte buf[bs+1];
        int buf_sz=0;
        int rcv_sz=0;
        char errmsg[215] = "";

        /*dhsocket_recv(sock.cfd, buf, bs);*/
        retry_num = 0;
    retry0:
        try_continue(1,0);
        ret = dhsocket_recv_exp(sock.cfd, &buf_sz, sizeof(buf_sz),MSG_KEX_DH_GEX_INIT_SZ);
        try_continue(0,1);
        if(ret !=0&&retry_num<5) {
            printf("ret of MSG_KEX_DH_GEX_INIT_SZ is %d, retry num is %d\n", ret, retry_num);
            retry_num++;
            goto retry0;
        } else if(retry_num>=5) {
            goto err_ret;
        }
        rcv_sz = ntohl(buf_sz);
#ifdef DEBUG
        printf("<[%s:%d:%s] pid(%d) Pubkey size from client is %d\n",__FILE__,__LINE__,__func__, getpid(),rcv_sz);
#endif

        retry_num = 0;
    retry1:
        try_continue(1,0);
        ret = dhsocket_recv_exp(sock.cfd, buf, rcv_sz,MSG_KEX_DH_GEX_INIT);
        try_continue(0,1);
        if(ret !=0&&retry_num<5) {
            printf("ret of MSG_KEX_DH_GEX_INIT is %d, retry num is %d\n", ret, retry_num);
            retry_num++;
            goto retry1;
        } else if(retry_num>=5) {
            goto err_ret;
        }

        buf[rcv_sz] = '\0';
#ifdef DEBUG
        sprintf(errmsg, "<[%s:%d:%s] pid(%d) Pubkey from client",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, buf, bs);
        try_continue(0,1);
#endif

        ztca_AllocData(NULL, &remote_data, (rcv_sz+1));
        memcpy(remote_data.data, buf, rcv_sz);
        remote_data.len = rcv_sz;
        agreedSecretLens = 0;
        if ((agreedSecrets =
                 nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLens)) == NULL) {
            goto err_ret;
        }

        int stat = nzdh_KeyAgreePhase2(ksize, nzdh_svr_ctx->cryptoCtx,remote_data,agreedSecrets,
                                       (unsigned int*)&agreedSecretLens,nzdh_svr_ctx);
#ifdef DEBUG
        sprintf(msg, "nzdh_KeyAgreePhase2 agreedSecret size %d", agreedSecretLens);
        sprintf(errmsg, ">[%s:%d:%s] pid(%d) AgreeSecret with server",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
        try_continue(0,1);
        TZTCA_PRN_STAT(msg, stat);
#endif
        {
            try_continue(1,0);
            dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_REPLY, agreedSecrets, agreedSecretLens);
            try_continue(0,1);
        }
    }
    {
        /*step3: verify final state from client */
        byte final_rec[5];
        int ret = 0;
        /*dhsocket_recv(sock.cfd, final_rec, sizeof(final_rec) - 1);*/
        retry_num=0;
    retry2:
        try_continue(1,0);
        ret = dhsocket_recv_exp(sock.cfd, final_rec, sizeof(final_rec) - 1, MSG_KEX_DH_GEX_INTERIM);
        try_continue(0,1);
        if(ret !=0 && retry_num<5) {
            printf("ret of MSG_KEX_DH_GEX_INTERIM is %d, retry num is %d\n", ret, retry_num);
            retry_num++;
            goto retry2;
        } else if(retry_num>=5) {
            goto err_ret;
        }

        final_rec[4] = '\0';
        if(constantVerify(final_rec, (byte*)"Fail") == 1) {
            char errmsg[215] = "";
            printf("Secret sharing failed\n");
            try_continue(1,0);
            sprintf(errmsg, ">[%s:%d:%s] pid(%d) Pubkey with server", __FILE__,__LINE__,__func__,getpid());
            _gp_dumpBuf(0, errmsg, nzdh_svr_ctx->publicValue, nzdh_svr_ctx->publicValueLen);
            sprintf(errmsg, "<[%s:%d:%s] pid(%d) Pubkey from client",__FILE__,__LINE__,__func__, getpid());
            _gp_dumpBuf(0, errmsg, remote_data.data, remote_data.len);
            sprintf(errmsg, ">[%s:%d:%s] pid(%d) AgreeSecret with server",__FILE__,__LINE__,__func__, getpid());
            _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
            try_continue(0,1);
            goto err_ret;
        } else if(constantVerify(final_rec, (byte*)"Succ") == 1) {
#ifdef DEBUG
            printf("Secret sharing succeeded\n");
#endif
            /**/
        } else {
            goto err_ret;
        }
    }
    stat = 0;
    /* end TUX DH exchange key protocol*/
    err = ztca_Shutdown();
    if (err != ZTERR_OK) {
        TZTCA_PRN_RES("ztca_Shutdown - ", TZTCA_ERR_SHUTDOWN & err);
        stat = TZTCA_ERR_INIT;
    }
err_ret:
    /*
    if(remote_data.data)
        ztca_FreeData(&remote_data,FALSE);
    */
    if(nzdh_svr_ctx!=NULL) {
        if(nzdh_svr_ctx->cryptoCtx)
            ztca_DestroyCryptoCtx(nzdh_svr_ctx->cryptoCtx);
        free(nzdh_svr_ctx);
        nzdh_svr_ctx=NULL;
    }
    close(sock.cfd);
    exit(0);
}

int main(int argc, char *argv[]) {
    int cc = 0;
    int sc = 0;
    dhsocket_t sock;
    struct sigaction act;       /* Signal handler specification structure */
    int fd;

    if(argc != 2 || sc != 0) {
        printf("Usage %s <port> \n",argv[0]);
        goto err_ret;
    }

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1)
        perror("open");
    glob_var = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (glob_var == MAP_FAILED)
        perror("mmap");
    *glob_var = 1;


    s_memclr(&act, sizeof(act));
    /* Set sig_child() as handler function */
    act.sa_handler =  sig_child;
    if (sigfillset(&act.sa_mask) < 0)   /* mask all signals */
        diewitherror("sigfillset() failed");
    /* SA_RESTART causes interrupted system calls to be restarted */
    act.sa_flags = SA_RESTART;

    /* Set signal disposition for child-termination signals */
    if (sigaction(SIGCHLD, &act, 0) < 0)
        diewitherror("sigaction() failed");

    s_memclr(&sock, sizeof(dhsocket_t));

    sc = dhsocket_init(&sock);

    if(dhsocket_serv_start(&sock,atoi(argv[1])) == 0)
        goto err_ret;

    for (;;) {
        while ( ChildCount >= MAXCLIENTS )
            sleep(1);  /*---You could "sched_yield()" instead---*/

        dhsocket_serv_accept(&sock);

        if ( sock.cfd > 0 ) {
            int pid;

            if ( (pid = fork()) == 0 ) {
                /*---CHILD---*/
                close(sock.sfd);
                child(sock); /*---Serve the new client---*/
            } else if ( pid > 0 ) {
                /*---PARENT---*/
                close(sock.cfd);
                ChildCount++;


            } else
                perror("fork() failed");
        }
    }

err_ret:
    dhsocket_close(&sock);
    exit(0);

}
