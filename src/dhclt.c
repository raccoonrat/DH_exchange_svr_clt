#include <tux_ztdh.h>
#include <dhsocket.h>
#include <dhutils.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <tas.h>

#define DEFAULT_DURATION 50 /* default duration is 60 second*/

static inline int count(int x)
{
    return floor(log10(x)) + 1;
}

int NumChildren=0;

volatile int *glob_var;

void sig_child()
{
    pid_t processID;           /* Process ID from fork() */

    while (NumChildren)   /* Clean up all zombies */
    {
        processID = waitpid((pid_t) -1, NULL, WNOHANG);  /* Non-blocking wait */
        if (processID < 0)  /* waitpid() error? */
            diewitherror("waitpid() failed");
        else if (processID == 0)  /* No child to wait on */
            break;
        else
        {
            try_continue(1,0);
            NumChildren--;  /* Cleaned up after a child */
            try_continue(0,1);
        }
    }
}

void child(char *address, int portnum)
{
    zterr err;
    int stat = 0;
    int i;
    unsigned int ksize = sizeof(dhParamsBER128);

    int cc = 0;
    int sc = 0;
    unsigned int minP;
    unsigned int iP;
    unsigned int maxP;

    dhsocket_t sock;

    GPE_DH_CONTEXT_T *nzdh_clt_ctx = NULL;
    unsigned char    *agreedSecrets = NULL; /* Agreed key */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    ztcaData other ;
    byte initBuf[13];
    char msg[32];
    int retry_num = 0;

    s_memclr(&sock, sizeof(dhsocket_t));
    s_memclr(&other, sizeof(ztcaData));
    sc = dhsocket_init(&sock);

    minP = 256;
    iP = 414;   /* TUXEDO NZSDK static prime argument defined in tux_ztdh.h*/
    maxP = 4096;

    try_continue(1,0);
    glob_var[0]++;
    try_continue(0,1);
#ifdef DEBUG
    printf("<pid=%d>num of child=%d\n",getpid(),glob_var[0]);
#endif

    if(dhsocket_client_start(&sock,address,portnum) == 0)
        goto err_ret;

    err = ztca_Init(FALSE);
    if (err != ZTERR_OK)
    {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        err |= TZTCA_ERR_INIT;
        goto err_ret;
    }
    /* start TUX NZ DH protocol */
    {
        /*step 1: nzdh_KeyAgreePhase1 include ztca_GenerateKey, ztca_CreatePubKeyCtx and ztca_DHGenPubValue*/
        char errmsg[215] = "";
        int stat = nzdh_KeyAgreePhase1(ksize, (GPE_DH_CONTEXT_T**)&nzdh_clt_ctx);
        {
            int converted_number = htonl(nzdh_clt_ctx->publicValueLen);
            try_continue(1,0);
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INIT_SZ, (byte*)&(converted_number), sizeof(converted_number));
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INIT, (byte*)nzdh_clt_ctx->publicValue, nzdh_clt_ctx->publicValueLen);
            try_continue(0,1);
        }
#ifdef DEBUG

        sprintf(errmsg, ">[%s:%d:%s] pid(%d)Pubkey with client",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, nzdh_clt_ctx->publicValue , nzdh_clt_ctx->publicValueLen);
        try_continue(0,1);
        sprintf(msg, "nzdh_KeyAgreePhase1 key size %d, pubkey size %d", ksize,nzdh_clt_ctx->publicValueLen);
        TZTCA_PRN_STAT(msg, stat);
#endif
    }
    {
        /*step2: get pubkey from svr and invoke nzdh_KeyAgreePhase2 */
        unsigned int bs = nzdh_clt_ctx->publicValueLen;
        byte buf[bs+1];
        int buf_sz = 0;
        int rcv_sz = 0;
        int ret = 0;
        char errmsg[215] = "";
        s_memclr(buf, (bs+1)*sizeof(byte));
        /*dhsocket_recv(sock.sfd, buf, bs);*/
        retry_num = 0;
    retry0:
        try_continue(1,0);
        ret = dhsocket_recv_exp(sock.sfd, (byte*)&buf_sz, sizeof(buf_sz),MSG_KEX_DH_GEX_GROUP_SZ);
        try_continue(0,1);
        if(ret!=0 && retry_num <5)
        {
            printf("ret of MSG_KEX_DH_GEX_GROUP_SZ is %d, retry_num=%d\n", ret, retry_num);
            retry_num++;
            goto retry0;
        }
        else if(retry_num>=5)
        {
            goto err_ret;
        }
        rcv_sz = ntohl(buf_sz);
#ifdef DEBUG
        printf("<[%s:%d:%s] pid(%d)Pubkey size from server is %d\n",__FILE__,__LINE__,__func__, getpid(),rcv_sz);
#endif

        retry_num = 0;
    retry1:
        try_continue(1,0);
        ret = dhsocket_recv_exp(sock.sfd, buf, rcv_sz,MSG_KEX_DH_GEX_GROUP);
        try_continue(0,1);
        if(ret!=0 && retry_num <5)
        {
            printf("ret of MSG_KEX_DH_GEX_GROUP is %d, retry_num=%d\n", ret, retry_num);
            retry_num++;
            goto retry1;
        }
        else if(retry_num>=5)
        {
            goto err_ret;
        }
        buf[rcv_sz] = '\0';

        ztca_AllocData(NULL, &other, (rcv_sz+1));
        memcpy(other.data, buf, rcv_sz);
        other.len = rcv_sz;
#ifdef DEBUG
        sprintf(errmsg, "<[%s:%d:%s] pid(%d)Pubkey from server",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, other.data, other.len);
        try_continue(0,1);
#endif
        agreedSecretLens = 0;
        if ((agreedSecrets =
                 nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLens)) == NULL)
        {
            goto err_ret;
        }
        int stat = nzdh_KeyAgreePhase2(ksize, nzdh_clt_ctx->cryptoCtx,other,agreedSecrets,
                                       (unsigned int*)&agreedSecretLens,nzdh_clt_ctx);
#ifdef DEBUG
        sprintf(msg, "nzdh_KeyAgreePhase2 agreedSecret size %d", agreedSecretLens);
        TZTCA_PRN_STAT(msg, stat);
#endif
    }
    {
        /*step4: verify remoter agreed key and send final msg */
        unsigned int bs = agreedSecretLens;
        byte buf[bs+1];
        int ret = 0;
        char errmsg[215] = "";
        /*dhsocket_recv(sock.sfd, buf, bs);*/
        s_memclr(buf, (bs+1)*sizeof(byte));
        retry_num=0;
    retry2:
        try_continue(1,0);
        ret = dhsocket_recv_exp(sock.sfd, buf, bs,MSG_KEX_DH_GEX_REPLY);
        try_continue(0,1);

        if(ret!=0 && retry_num <5)
        {
            printf("ret of MSG_KEX_DH_GEX_REPLY is %d, retry_num=%d\n", ret, retry_num);
            retry_num++;
            goto retry2;
        }
        else if(retry_num>=5)
        {
            goto err_ret;
        }
        buf[bs] = '\0';

#ifdef DEBUG
        sprintf(errmsg, "<[%s:%d:%s] pid(%d)AgreeSecret from server ",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, buf, bs);
        try_continue(0,1);
        sprintf(errmsg, ">[%s:%d:%s] pid(%d)AgreeSecret with client",__FILE__,__LINE__,__func__, getpid());
        try_continue(1,0);
        _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
        try_continue(0,1);
#endif
        if(memcmp(agreedSecrets, buf, bs)!=0|| ret !=0)
        {
            char sec_msg[] = "Fail";
            char errmsg[215] = "";

            try_continue(1,0);
            glob_var[1]++;
#ifdef DEBUG
            printf("<pid=%d>failed num=%d\n",getpid(),glob_var[1]);
#endif
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INTERIM, (byte*)sec_msg, strlen(sec_msg));
            try_continue(0,1);

            try_continue(1,0);
            printf("Secret sharing failed, return code of dhsocket_recv_exp is %d\n",ret);
            sprintf(errmsg, "<[%s:%d:%s] pid(%d) Pubkey from server",__FILE__,__LINE__,__func__, getpid());
            _gp_dumpBuf(0, errmsg, other.data, other.len);
            sprintf(errmsg, ">[%s:%d:%s] pid(%d) Pubkey with client",__FILE__,__LINE__,__func__, getpid());
            _gp_dumpBuf(0, errmsg, nzdh_clt_ctx->publicValue , nzdh_clt_ctx->publicValueLen);
            sprintf(errmsg,"<[%s:%d:%s] pid(%d) AgreeSecret from server",__FILE__,__LINE__,__func__, getpid());
            _gp_dumpBuf(0, errmsg, buf, bs);
            sprintf(errmsg,">[%s:%d:%s] pid(%d) AgreeSecret with client",__FILE__,__LINE__,__func__, getpid());
            _gp_dumpBuf(0, errmsg, agreedSecrets, agreedSecretLens);
            try_continue(0,1);
            goto err_ret;
        }
        else
        {
            char sec_msg[] = "Succ";
            try_continue(1,0);
            glob_var[2]++;
#ifdef DEBUG
            printf("<pid=%d>success num=%d\n",getpid(),glob_var[2]);
#endif
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INTERIM, (byte*)sec_msg, strlen(sec_msg));
            try_continue(0,1);

#ifdef DEBUG
            printf("Secret sharing succeeded\n");
#endif
        }
    }
    /* end TUX NZ DH protocol */

err_ret:
    poll(0,0,100);  /* wait .1s */
    err = ztca_Shutdown();
    if (err != ZTERR_OK)
    {
        TZTCA_PRN_RES("ztca_Shutdown - ", TZTCA_ERR_SHUTDOWN & err);
        stat = TZTCA_ERR_INIT;
    }
    munmap(glob_var, 10*sizeof(int)) ;

    ztca_FreeData(&other,FALSE);

    close(sock.sfd);
    exit(0);
}

int main(int argc, char *argv[])
{
    int child_count=0;
    time_t start;
    int fd;
    int duration = DEFAULT_DURATION, xdua=0;
    struct sigaction act;
    char *hostname = NULL;
    char *addr = NULL;

    if(argc < 4 )
    {
        printf("Usage %s <hostname> <port> <duration>\n",argv[0]);
        exit(0);
    }
    if(argv[3])
    {
        xdua = atoi(argv[3]);
        if(xdua!=0)
            duration = xdua;
#ifdef DEBUG
        printf("input dua=%d, duration=%d seconds\n",xdua,duration);
#endif
    }

    hostname = argv[1];
    addr = dhsocket_resolvename(hostname);
    if(addr == NULL)
        diewitherror("cannot get the hostname");
#ifdef DEBUG
    printf("clt ip addr is %s\n",addr);
#endif

    time(&start);
    bzero(&act, sizeof(act));
    /* Set sig_child() as handler function */
    act.sa_handler =  sig_child;
    if (sigfillset(&act.sa_mask) < 0)   /* mask all signals */
        diewitherror("sigfillset() failed");
    /* SA_RESTART causes interrupted system calls to be restarted */
    act.sa_flags = SA_RESTART;

    /* Set signal disposition for child-termination signals */
    if (sigaction(SIGCHLD, &act, 0) < 0)
        diewitherror("sigaction() failed");

    fd = open("/dev/zero", O_RDWR);
    if (fd == -1)
        perror("open");
    glob_var = mmap(NULL, 10*sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (glob_var == MAP_FAILED)
        perror("mmap");
    s_memclr(glob_var, (10)*sizeof(int));

    while ( time(0) - start < duration )
    {
        if ( NumChildren < 2 )
        {
            int PID;

            if ( (PID = fork()) == 0 )
            {
                child(addr,atoi(argv[2]));
            }
            else if ( PID > 0 )
            {
                /*printf("child #%d\r", ++child_count);*/
                try_continue(1,0);
                NumChildren++;
                try_continue(0,1);
            }
            else
            {
                perror("fork() failed");
            }
        }
        else
            sleep(1);
    }
    while ( NumChildren > 0 )
        sleep(1);
    printf("In duration %d seconds,total test num [%d], failed num [%d], success num [%d]\n",duration,glob_var[0],glob_var[1],glob_var[2]);
    munmap(glob_var, 3*sizeof(int));
    return 0;
}

