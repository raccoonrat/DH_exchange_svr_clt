#include <tux_ztdh.h>
#include <dhsocket.h>
#include <dhutils.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>


static inline int count(int x) {
    return floor(log10(x)) + 1;
}

int main(int argc, char *argv[]) {
    zterr err;
    int stat = 0;
    char *buff;
    int i;
    /*unsigned int ksize = sizeof(zt_base_dhParamsBER128);*/
    unsigned int ksize = sizeof(dhParamsBER128);

    int status = -1;
    int cc = 0;
    int sc = 0;
    byte minnmax_buf[12];
    byte minP[5];
    byte iP[5];
    byte maxP[5];
    unsigned int uminP = 0;
    unsigned int uiP = 0;
    unsigned int umaxP = 0;
    unsigned int resP = 0;
    unsigned int tresP = 0;
    dhsocket_t sock;

    GPE_DH_CONTEXT_T *nzdh_svr_ctx = NULL;
    unsigned char    *agreedSecrets = NULL; /* Agreed key */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    ztcaData          remote_data;
    byte             *s_verkey = NULL;
    char              msg[32];

    s_memclr(&sock, sizeof(dhsocket_t));
    s_memclr(&remote_data, sizeof(ztcaData));

    sc = dhsocket_init(&sock);

    if(argc != 2 || cc != 0 || sc != 0) {
        printf("Usage %s <port> \n",argv[0]);
        goto err_ret;
    }

    if(dhsocket_serv_start(&sock,atoi(argv[1])) == 0)
        goto err_ret;

    dhsocket_serv_accept(&sock);

    err = ztca_Init(FALSE);
    if (err != ZTERR_OK) {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        return TZTCA_ERR_INIT;
    }
    /* start TUX DH exchange key protocol*/
    {
        /*step1: svr generateParameters, send svr pub to client as reply*/
        int stat = nzdh_KeyAgreePhase1(ksize,(GPE_DH_CONTEXT_T**)&nzdh_svr_ctx);
        {
            dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_GROUP, nzdh_svr_ctx->publicValue, nzdh_svr_ctx->publicValueLen);
            _gp_dumpBuf(0, "> Pubkey with server", nzdh_svr_ctx->publicValue, nzdh_svr_ctx->publicValueLen);
        }
        sprintf(msg, "nzdh_KeyAgreePhase1 key size %d", ksize);
        TZTCA_PRN_STAT(msg, stat);
    }
    {
        /*step2: recv client pubkey*/
        unsigned int bs = nzdh_svr_ctx->publicValueLen;
        byte buf[bs+1];

        dhsocket_recv(sock.cfd, buf, bs);
        buf[bs] = '\0';
        _gp_dumpBuf(0, "< Pubkey from client", buf, bs);

        ztca_AllocData(NULL, &remote_data, bs);
        memcpy(remote_data.data, buf, bs);
        remote_data.len = nzdh_svr_ctx->keyLenSelection;
        agreedSecretLens = 0;
        if ((agreedSecrets =
                 nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLens)) == NULL) {
            goto err_ret;
        }

        int stat = nzdh_KeyAgreePhase2(ksize, nzdh_svr_ctx->cryptoCtx,remote_data,agreedSecrets,
                                       (unsigned int*)&agreedSecretLens,nzdh_svr_ctx);
        sprintf(msg, "nzdh_KeyAgreePhase2 agreedSecret size %d", agreedSecretLens);
        _gp_dumpBuf(0, "> AgreeSecret with server", agreedSecrets, agreedSecretLens);
        TZTCA_PRN_STAT(msg, stat);
        {
            dhsocket_send(sock.cfd, MSG_KEX_DH_GEX_REPLY, agreedSecrets, agreedSecretLens);
        }
    }
    {
        /*step3: verify final state from client */
        byte final_rec[5];
        dhsocket_recv(sock.cfd, final_rec, sizeof(final_rec) - 1);
        final_rec[4] = '\0';

        if(constantVerify(final_rec, (byte*)"Fail") == 1) {
            goto err_ret;
        } else if(constantVerify(final_rec, (byte*)"Succ") == 1) {
            printf("Secret sharing succeeded\n");
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
    ztca_FreeData(&remote_data,FALSE);
    /*
        ztca_DestroyCryptoCtx(nzdh_svr_ctx->cryptoCtx);
        if(nzdh_svr_ctx!=NULL) {
            free(nzdh_svr_ctx);
            nzdh_svr_ctx=NULL;
        }
    */
    dhsocket_close(&sock);

    return stat;
}

