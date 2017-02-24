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
    unsigned int minP;
    unsigned int iP;
    unsigned int maxP;
    unsigned int resP = 0;
    unsigned int hsign_len = 0;
    byte* hsign = NULL;
    dhsocket_t sock;

    GPE_DH_CONTEXT_T *nzdh_clt_ctx = NULL;
    unsigned char    *agreedSecrets = NULL; /* Agreed key */
    unsigned int      agreedSecretLens = 0; /* The length of the pn */
    ztcaData other ;
    byte initBuf[13];
    char msg[32];

    if(argc != 3 || sc != 0) {
        printf("Usage %s <hostname> <port> \n",argv[0]);
        goto err_ret;
    }

    s_memclr(&sock, sizeof(dhsocket_t));
    s_memclr(&other, sizeof(ztcaData));
    sc = dhsocket_init(&sock);

    minP = 256;
    iP = 414;   /* TUXEDO NZSDK static prime argument defined in tux_ztdh.h*/
    maxP = 4096;

    if(dhsocket_client_start(&sock,argv[1],atoi(argv[2])) == 0)
        goto err_ret;

    err = ztca_Init(FALSE);
    if (err != ZTERR_OK) {
        TZTCA_PRN_RES("ztca_Init - ", TZTCA_ERR_INIT & err);
        return TZTCA_ERR_INIT;
    }
    /* start TUX NZ DH protocol */
    {
        /*step 1: nzdh_KeyAgreePhase1 include ztca_GenerateKey, ztca_CreatePubKeyCtx and ztca_DHGenPubValue*/
        int stat = nzdh_KeyAgreePhase1(ksize, (GPE_DH_CONTEXT_T**)&nzdh_clt_ctx);
        {
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INIT, (byte*)nzdh_clt_ctx->publicValue, nzdh_clt_ctx->publicValueLen);
        }
        _gp_dumpBuf(0, "> Pubkey with client", nzdh_clt_ctx->publicValue , nzdh_clt_ctx->publicValueLen);
        sprintf(msg, "nzdh_KeyAgreePhase1 key size %d, pubkey size %d", ksize,nzdh_clt_ctx->publicValueLen);
        TZTCA_PRN_STAT(msg, stat);
    }
    {
        /*step2: get pubkey from svr and nzdh_KeyAgreePhase2 */
        unsigned int bs = nzdh_clt_ctx->publicValueLen;
        byte buf[bs+1];
        dhsocket_recv(sock.sfd, buf, bs);
        buf[bs] = '\0';
        ztca_AllocData(NULL, &other, bs);

        memcpy(other.data, buf, bs);
        other.len = nzdh_clt_ctx->keyLenSelection;
        _gp_dumpBuf(0, "< Pubkey from server", other.data, other.len);
        agreedSecretLens = 0;
        if ((agreedSecrets =
                 nzdh_AllocAgreedSecretKey((unsigned int *)&agreedSecretLens)) == NULL) {
            goto err_ret;
        }
        int stat = nzdh_KeyAgreePhase2(ksize, nzdh_clt_ctx->cryptoCtx,other,agreedSecrets,
                                       (unsigned int*)&agreedSecretLens,nzdh_clt_ctx);
        sprintf(msg, "nzdh_KeyAgreePhase2 agreedSecret size %d", agreedSecretLens);
        TZTCA_PRN_STAT(msg, stat);
    }
    {
        /*step4: verify remoter agreed key and send final msg */
        unsigned int bs = agreedSecretLens;
        byte buf[bs+1];
        dhsocket_recv(sock.sfd, buf, bs);
        buf[bs] = '\0';

        _gp_dumpBuf(0, "< AgreeSecret from server", buf, bs);
        _gp_dumpBuf(0, "> AgreeSecret with client", agreedSecrets, agreedSecretLens);

        if(memcmp(agreedSecrets, buf, bs)!=0) {
            char sec_msg[] = "Fail";
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INTERIM, (byte*)sec_msg, strlen(sec_msg));
            goto err_ret;
        } else {
            char sec_msg[] = "Succ";
            dhsocket_send(sock.sfd, MSG_KEX_DH_GEX_INTERIM, (byte*)sec_msg, strlen(sec_msg));
            printf("Secret sharing succeeded\n");
        }
    }
    status = 0;
    /* end TUX NZ DH protocol */

    err = ztca_Shutdown();
    if (err != ZTERR_OK) {
        TZTCA_PRN_RES("ztca_Shutdown - ", TZTCA_ERR_SHUTDOWN & err);
        stat = TZTCA_ERR_INIT;
    }
err_ret:
    ztca_FreeData(&other,FALSE);
    /*
        ztca_DestroyCryptoCtx(nzdh_clt_ctx->cryptoCtx);
        if(nzdh_clt_ctx!=NULL) {
            free(nzdh_clt_ctx);
            nzdh_clt_ctx=NULL;
        }
    */
    dhsocket_close(&sock);

    return stat;
}

