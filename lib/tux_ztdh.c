#include <dhutils.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <tztca.h>
#include <tux_ztdh.h>


/* input :
 *       unsigned int   lenBits
 *       GPE_DH_CONTEXT_T **nzdh_ctx(malloc in nzdh_KeyAgreePhase1)
 * output:
 *       GPE_DH_CONTEXT_T **nzdh_ctx
 */
int nzdh_KeyAgreePhase1(unsigned int lenBits, GPE_DH_CONTEXT_T **nzdh_ctx)
{
    zterr             err= ZTERR_OK;
    zterr             status = ZTERR_OK;
    ztcaPubKeyAlgType alg = ZTCA_PALG_DH;
    ztcaKey          *key = NULL;
    ztcaCryptoOpType  op = ZTCA_EXCHANGE;
    ztcaKeyParams     keyParams; /* add primeLenInBits and generator order */
    ztcaDHKeyParams   *dhParams  = &keyParams.u.pubKeyParams.u.dhParams;
    GPE_DH_CONTEXT_T  *context   = NULL;
    unsigned int plen, len;
    struct timeval tv, tv_new;
    unsigned long msec;
    ztcaCryptoCtx *cryptoCtx = NULL;

    /* Check input arguments */
    if (lenBits == 0 || nzdh_ctx == NULL)
    {
        goto err_ret;
    }

    if (alg != ZTCA_PALG_DH && alg != ZTCA_PALG_ECDH && alg != ZTCA_PALG_ECDHC)
    {
        return TZTCA_ERR_ARG;
    }
    /* allocate context */
    if ((context = (GPE_DH_CONTEXT_T *)malloc(sizeof(GPE_DH_CONTEXT_T))) == NULL)
    {
        return TZTCA_ERR_ARG;
    }
    (void)memset((char *)context, 0, sizeof(GPE_DH_CONTEXT_T));
    memset(&keyParams, 0, sizeof(keyParams));

    /* Fill in DH parameter, setup return of Prime numbers */
    keyParams.keyType = ZTCA_PUBKEY_PARAMS;
    keyParams.u.pubKeyParams.keyType = ZTCA_PKEY_DH_PARAMS;
    if (lenBits == sizeof(dhParamsBER128))
    {
        dhParams->generator.data = zt_base_dhParamsBER128;
        dhParams->generator.len  = sizeof(zt_base_dhParamsBER128);
        dhParams->modulus.data   = zt_prime_dhParamsBER128;
        dhParams->modulus.len    = sizeof(zt_prime_dhParamsBER128);
    }
    else
    {
        dhParams->generator.data = zt_base_dhParamsBER40;
        dhParams->generator.len  = sizeof(zt_base_dhParamsBER40);
        dhParams->modulus.data   = zt_prime_dhParamsBER40;
        dhParams->modulus.len    = sizeof(zt_prime_dhParamsBER40);
    }
    dhParams->pkey.data = NULL;
    dhParams->pkey.len  = 0;
    keyParams.u.pubKeyParams.u.dhParams.primeBits = lenBits;
    context->keyLenSelection = dhParams->modulus.len;
    TZTCA_START_TIME(tv);
    err = ztca_GenerateKey(NULL, &keyParams, NULL, &key);
    TZTCA_STOP_TIME_MSEC(tv, tv_new, msec);
    if (err != ZTERR_OK)
    {
        err |= TZTCA_ERR_ASM_CTX_CREATE;
        goto err_ret;
    }
    TZTCA_PRN_UINT("    Param generation time: ", msec);

    err = ztca_CreatePubKeyCtx(NULL, key, alg, op, &cryptoCtx);
    if (err != ZTERR_OK)
    {
        err |= TZTCA_ERR_KE_CTX_CREATE;
        goto err_ret;
    }
    context->publicValueLen = sizeof(context->publicValue);

    err = ztca_DHGenPubValue(cryptoCtx, context->publicValue, &context->publicValueLen);
    if (err != ZTERR_OK)
    {
        err |= TZTCA_ERR_KE_PUB_VAL;
        goto err_ret;
    }
    else
    {
        context->cryptoCtx = cryptoCtx;
        *nzdh_ctx = context;
    }
    ztca_DestroyKey(key, FALSE);

    return ZTERR_OK;
err_ret:
    if (context != NULL)
    {
        free(context);
        context = NULL;
    }
    return err;
}


unsigned char *
nzdh_AllocAgreedSecretKey(unsigned int *sizep)
{
    unsigned char *tmp = (unsigned char *)calloc(1,sizeof(zt_base_dhParamsBER128));
    if (tmp == NULL)
    {
        *sizep = 0;
    }
    else
    {
        *sizep = sizeof(zt_base_dhParamsBER128);
    }
    return tmp;
}

/* input :
 *       ztcaCryptoCtx *cryptoCtx
 *       ztcaData      *pub_remote
 *       ztcaData      *sess_local
 *       unsigned int   lenBits
 * output:
 *       ztcaData      *sess_local
 */
int nzdh_KeyAgreePhase2(unsigned int lenBits, ztcaCryptoCtx *cryptoCtx, ztcaData pub_remote,
                        unsigned char *agreedSecret, unsigned int *agreedSecretLen, GPE_DH_CONTEXT_T  *context )
{
    zterr err;
    ztcaPubKeyAlgType alg = ZTCA_PALG_DH;
    ztcaCryptoOpType op = ZTCA_EXCHANGE;
    unsigned int plen, len;


    struct timeval tv, tv_new;
    unsigned long msec;

    /* Check input arguments */
    if (context == NULL ||
        agreedSecret == NULL || agreedSecretLen == NULL)
    {
        return TZTCA_ERR_ARG;
    }

    if (context->agreedSecretLen == 0)
    {
        unsigned char *tmp = NULL;
        context->agreedSecretLen = sizeof(context->agreedSecret);
        TZTCA_START_TIME(tv);
        err = ztca_DHGenSharedSecret(context->cryptoCtx, pub_remote.data, pub_remote.len,
                                     context->agreedSecret, &context->agreedSecretLen);
        TZTCA_STOP_TIME_MSEC(tv, tv_new, msec);
        if (err != ZTERR_OK)
        {
            context->agreedSecretLen = 0;
            err |= TZTCA_ERR_KE_SESS_KEY;
            TZTCA_PRN_UINT("    Shared secret generation failed time: ", msec);
            goto err_ret;
        }
        else
        {
            (void)memcpy(agreedSecret, context->agreedSecret,
                         context->agreedSecretLen);
        }
        *agreedSecretLen = context->agreedSecretLen;
        TZTCA_PRN_UINT("    Shared secret generation time: ", msec);
    }

    return ZTERR_OK;
err_ret:
    return err;
}


void nzdh_destroy(ztcaCryptoCtx *cryptoCtx, ztcaData pub, ztcaData sess)
{
    ztca_FreeData(&sess, FALSE);
    ztca_FreeData(&pub, FALSE);
    ztca_DestroyCryptoCtx(cryptoCtx);

    return ;
}

void nzdh_destroy_1(ztcaCryptoCtx *cryptoCtx)
{
    ztca_DestroyCryptoCtx(cryptoCtx);

    return ;
}


int digestBuff(ub1* in, ub4 inlen,
               ub1 *out, ub4* outlen, ztcaDigestAlgType hashType)
{

    zterr err;
    ztcaCryptoCtx *crypCtx = NULL;
    int stat = PASSED;

    err = ztca_CreateDigestCtx(NULL, hashType, NULL, &crypCtx);
    if (err != ZTERR_OK)
    {
        return TZTCA_ERR_DST_CREATE_CTX | err;
    }

    err = ztca_DigestInit(crypCtx);
    if (err != ZTERR_OK)
    {
        return TZTCA_ERR_DST_INIT | err;
    }

    err = ztca_DigestUpdate(crypCtx, in, inlen);
    if (err != ZTERR_OK)
    {
        return TZTCA_ERR_DST_UPDATE | err;
    }

    err = ztca_DigestFinish(crypCtx, out, outlen);
    if (err != ZTERR_OK)
    {
        return TZTCA_ERR_DST_FINISH | err;
    }
    stat = PASSED;

    err = ztca_DestroyCryptoCtx(crypCtx);
    if (err != ZTERR_OK)
    {
        stat = TZTCA_ERR_DST_DESTROY | err;
    }
    return stat;
}


int runDigestTestForType(ztcaDigestAlgType hashType)
{
    int stat;
    ub1 buf[1024];
    int i = 0;

    for (i = 32; i < RNG_BUFF_SIZE; i <<= 1)
    {
        ub4 len = i;
        ub1 rbuf[1024];

        /* XXX todo: check unaligned buff */
        stat = digestBuff(buf, len,
                          rbuf, &len, hashType);
        if (stat != PASSED)
        {
            return stat;
        }
        memcpy(buf, rbuf, len);
    }
    return PASSED;
}

int runDigestTests()
{
    int stat = 0;

    stat |= runDigestTestForType(ZTCA_DGST_MD5);
    TZTCA_PRN_RES("  running ZTCHTMD5", stat);
    stat |= runDigestTestForType(ZTCA_DGST_SHA1);
    TZTCA_PRN_RES("  running ZTCHTSH1", stat);
    stat |= runDigestTestForType(ZTCA_DGST_SHA224);
    TZTCA_PRN_RES("  running ZTCHTSH224", stat);
    stat |= runDigestTestForType(ZTCA_DGST_SHA256);
    TZTCA_PRN_RES("  running ZTCHTSH256", stat);
    stat |= runDigestTestForType(ZTCA_DGST_SHA384);
    TZTCA_PRN_RES("  running ZTCHTSH384", stat);
    stat |= runDigestTestForType(ZTCA_DGST_SHA512);
    TZTCA_PRN_RES("  running ZTCHTSH512", stat);
    return stat;
}



/*
 * _e_cryp_digest
 *
 * Gets the digest of a particular buffer.
 *
 * INPUT
 *  outbuf  - Not NULL.  Points to output space
 *  outbuf_sizep - Not NULL.
 *  *outbuf_sizep - Allocated size of outbuf
 *  inbuf   - Buffer to digest
 *  inbuf_size - Size of data in inbuf
 *  digalg  - Digest algorithm to use
 *
 * OUTPUT
 *  *outbuf_sizep - Amount of space needed if return 0
 *  *outbuf_sizep - Actual data size in outbuf if return 1
 *
 * RETURNS
 *  1   - Success
 *  0   - Need more space in outbuf
 *  -1  - Fatal error
 */
int
_e_cryp_digest(unsigned char *outbuf, unsigned int *outbuf_sizep,
               const unsigned char *inbuf, unsigned int inbuf_size,
               DIG_ALGS digalg)
{

    zterr    err = 0;
    ztcht    type;
    ztchd    hash;
    int     retplace = 0;       /* Where did I return from */
    int      len;
    unsigned int    partOut;        /* Output size */


    if ((outbuf == NULL) || (outbuf_sizep == NULL) || (inbuf == NULL))
    {
        printf("< _e_cryp_digest(20) -1\n");
        return(-1);
    }

    if (*outbuf_sizep < 16)
    {
        /* The various MD outputs */
        *outbuf_sizep = 16;
        printf("< _e_cryp_digest(30) 0 *outbuf_sizep=%lu\n",
               (unsigned long) *outbuf_sizep);
        return(0);
    }

    len = 16;  /* MD2,MD4, and MD5 */

    switch(digalg)
    {
        case DIG_MD2:
            type = ZTCHTMD2;
            goto err_ret;
        case DIG_MD4:
            type = ZTCHTMD4;
            break;
        case DIG_MD5:
            type = ZTCHTMD5;
            break;
        case DIG_SHA1:
            type = ZTCHTSH1;
            len  = 20;
            break;
        case DIG_SHA256:
            type = ZTCHTSH256;
            len  = 32;
            break;
        case DIG_SHA384:
            type = ZTCHTSH384;
            len  = 48;
            break;
        case DIG_SHA512:
            type = ZTCHTSH512;
            len  = 64;
            break;
        default:
            retplace = 20;
            goto err_ret;
    }

    /* check whether the output buffer is larger enough */
    if (*outbuf_sizep < len)
    {
        retplace      = 40;
        *outbuf_sizep = len;
        goto err_ret;
    }

    /* setup hash buffer */
    hash.l_ztchd = *outbuf_sizep;

    if ((err = ztch(&hash, type, (unsigned char *)inbuf, inbuf_size)) != ZTERR_OK)
    {
        retplace = 30;
        goto err_ret;
    }

    /* update with the actual digest length */
    (void)memcpy(outbuf, hash.d_ztchd, hash.l_ztchd);
    *outbuf_sizep = (unsigned int)hash.l_ztchd;
#ifdef DEBUG
    printf("< _e_cryp_digest(20) 1 *outbuf_sizep %lu\n",
           (unsigned long) *outbuf_sizep);
#endif
    return 1;

err_ret:
    printf("< _e_cryp_digest(30) -1\n");
    return -1;

}


#define MAXTIDENT 30

int
_sess_setupCtx(
    void *handle,
    unsigned char *agreedSecrets,
    unsigned int   agreedSecretLens,
    unsigned char *agreedSecretr,
    unsigned int   agreedSecretLenr,
    int     flag)
{
    unsigned char *agreedSecret;
    unsigned int   agreedSecretLen;
    unsigned char *fingerprint;
    unsigned int   fingerprintLen;
    unsigned char  keycombo[LLELENGTHINBYTES];
    int            i;
    unsigned int   len;

    char               sendPassword[MAXTIDENT + 10];
    char               recvPassword[MAXTIDENT + 10];
    int                sendKeyMaterialLen;
    int                recvKeyMaterialLen;
    char              *sendKeyMaterial;
    char              *recvKeyMaterial;
    AES_GCM_HANDLE_P_T myHandle;

//#define DEBUG
    if(handle==NULL)
    {
        printf("< ERROR: Invalid handle return -1\n");
        return -1;
    }

    if ((agreedSecretLens < LLELENGTHINBYTES) ||
        (agreedSecretLenr < LLELENGTHINBYTES))
    {
        printf("< ERROR: Invalid number of encryption bits return -1\n");
        return -1;
    }

    myHandle = handle;

    agreedSecretLen = agreedSecretLens + agreedSecretLenr;
    agreedSecret = (unsigned char *)malloc(agreedSecretLen);
    if (agreedSecret == NULL)
    {
        printf("< wsc_sess_setupCtx(20) return -1\n");
        return -1;
    }

    if (flag == FD_ATTR_RESPONDER)
    {
        (void)memcpy(agreedSecret, agreedSecretr, agreedSecretLenr);
        (void)memcpy(agreedSecret + agreedSecretLenr,
                     agreedSecrets, agreedSecretLens);
    }
    else
    {
        (void)memcpy(agreedSecret, agreedSecrets, agreedSecretLens);
        (void)memcpy(agreedSecret + agreedSecretLens,
                     agreedSecretr, agreedSecretLenr);
    }

    for (i = 0; i < LLELENGTHINBYTES; i++)
    {
        keycombo[i] = agreedSecrets[i] ^ agreedSecretr[i];
    }

    len = 16;

    /* test digest */
#if 0
    {
        int stat;
        ub1 buf[1024];
        int i = 0;
        memcpy(buf,keycombo,LLELENGTHINBYTES);
        {
            ub4 len = 16;
            ub1 rbuf[1024];

            /* XXX todo: check unaligned buff */
            stat = digestBuff(buf, len,
                              rbuf, &len, ZTCA_DGST_MD5);
            if (stat != PASSED)
            {
                return stat;
            }
            memcpy(buf, rbuf, len);
        }
        memcpy(fingerprint,buf,len);
    }/* test digest end */
#endif
    /*
        if(digestBuff(fingerprint, &len,
                            keycombo, LLELENGTHINBYTES, ZTCA_DGST_MD5) <0)
    */

    /*
        if (_e_cryp_digest( fingerprint, &len,
                            keycombo, LLELENGTHINBYTES, DIG_MD5) < 0)

        {
            free(agreedSecret);
            free(fingerprint);
            printf("< wsc_sess_setupCtx(50) return -1\n");
            return -1;
        }
    */

    /* _WSC_AESGCM_TEST TODO */
    memset(sendPassword,0, sizeof(sendPassword));
    memset(recvPassword,0, sizeof(recvPassword));
    /*
    strcpy(sendPassword,"abcdefgh");
    strcpy(recvPassword,"abcdefgh");
    */
    /* _WSC_AESGCM_TEST TODO end*/
    /*
     * Create final key materials
     */
    sendKeyMaterialLen = agreedSecretLen + 32;
    recvKeyMaterialLen = agreedSecretLen + 32;
    sendKeyMaterial = (char *)calloc(1, sendKeyMaterialLen);
    recvKeyMaterial = (char *)calloc(1, recvKeyMaterialLen);
    if (sendKeyMaterial == NULL ||
        recvKeyMaterial == NULL)
    {
        printf("ERROR: Failed to allocate memory for key material.\n");
        if (sendKeyMaterial != NULL)
        {
            free(sendKeyMaterial);
        }
        if (recvKeyMaterial != NULL)
        {
            free(recvKeyMaterial);
        }
        return -1;
    }
    (void)memcpy(sendKeyMaterial, agreedSecret, agreedSecretLen);
    (void)memcpy(sendKeyMaterial + agreedSecretLen,
                 sendPassword, 32);
    (void)memcpy(recvKeyMaterial, agreedSecret, agreedSecretLen);
    (void)memcpy(recvKeyMaterial + agreedSecretLen,
                 recvPassword, 32);

    /* use SHA 256 to generate AES256 key */
    len = 32;
#if defined(DEBUG)
    _gp_dumpBuf(0, "sendKeyMaterial", sendKeyMaterial, sendKeyMaterialLen);
    _gp_dumpBuf(0, "recvKeyMaterial", recvKeyMaterial, recvKeyMaterialLen);
#endif
    (void)memset((void*)myHandle->sendAesKey, 0, 32);
    (void)memset((void*)myHandle->recvAesKey, 0, 32);

    /*
        if(digestBuff((unsigned char*)myHandle->sendAesKey, &len,
                              sendKeyMaterial, sendKeyMaterialLen, ZTCA_DGST_SHA256) <0)
        {
            free(agreedSecret);
            free(fingerprint);
            printf("< wsc_sess_setupCtx(50) return -1\n");
            return -1;
        }
        if(digestBuff((unsigned char*)myHandle->recvAesKey, &len,
                              recvKeyMaterial, recvKeyMaterialLen, ZTCA_DGST_SHA256) <0)
        {
            free(agreedSecret);
            free(fingerprint);
            printf("< wsc_sess_setupCtx(50) return -1\n");
            return -1;
        }
    */
    /* test digest */
    {
        int stat;
        ub1 buf[1024];
        int i = 0;
        memcpy(buf,sendKeyMaterial, sendKeyMaterialLen);
        {
            ub4 len = 32;
            ub1 rbuf[1024];

            /* XXX todo: check unaligned buff */
            stat = digestBuff(buf, len,
                              rbuf, &len, ZTCA_DGST_SHA256);
            if (stat != PASSED)
            {
                printf("< _sess_setupCtx(70) return %d\n",stat);
                return stat;
            }
            memcpy(buf, rbuf, len);
            memcpy(myHandle->sendAesKey,buf,len);
        }

    }/* test digest end */
    /* test digest */
    {
        int stat;
        ub1 buf[1024];
        int i = 0;
        memcpy(buf,recvKeyMaterial, recvKeyMaterialLen);
        {
            ub4 len = 32;
            ub1 rbuf[1024];

            /* XXX todo: check unaligned buff */
            stat = digestBuff(buf, len,
                              rbuf, &len, ZTCA_DGST_SHA256);
            if (stat != PASSED)
            {
                printf("< _sess_setupCtx(80) return %d\n",stat);
                return stat;
            }
            memcpy(buf, rbuf, len);
            memcpy(myHandle->recvAesKey,buf,len);
        }
        len =32;
#if defined(DEBUG)
        try_continue(1,0);
        _gp_dumpBuf(0, "AES256 sendKey in _sess_setup():625", myHandle->sendAesKey, len);
        try_continue(0,1);

        try_continue(1,0);
        _gp_dumpBuf(0, "AES256 recvKey in _sess_setup():630", myHandle->recvAesKey, len);
        try_continue(0,1);
        printf("< _sess_setupCtx(60) return\n");
#endif
    }/* test digest end */


    /*
        (void)_e_cryp_digest( (unsigned char*)myHandle->sendAesKey, &len,
                              sendKeyMaterial, sendKeyMaterialLen, DIG_SHA256);
        (void)_e_cryp_digest( (unsigned char*)myHandle->recvAesKey, &len,
                              recvKeyMaterial, recvKeyMaterialLen, DIG_SHA256);
    */
    (void)memset(sendKeyMaterial, 0, sendKeyMaterialLen);
    (void)memset(recvKeyMaterial, 0, recvKeyMaterialLen);
    free(sendKeyMaterial);

    /* clean up */
    (void)memset(sendPassword, 0, sizeof(sendPassword));
    (void)memset(recvPassword, 0, sizeof(recvPassword));

#if defined(DEBUG)
    try_continue(1,0);
    _gp_dumpBuf(0, "AES256 sendKey", myHandle->sendAesKey, len);
    try_continue(0,1);

    try_continue(1,0);
    _gp_dumpBuf(0, "AES256 recvKey", myHandle->recvAesKey, len);
    try_continue(0,1);
    printf("< _sess_setupCtx(60) return\n");
#endif
#undef DEBUG
    return 0;
}

static char *
_toHexDigit(unsigned char c, char *ret)
{
    static char xdigit[] = "0123456789ABCDEF";
    unsigned char h;
    unsigned char l;
    char    *p = ret;

    h = (c & 0xf0) >> 4;
    l = c & 0x0f;

    *ret++ = xdigit[h];
    *ret   = xdigit[l];
    return p;
}

static void
_writeBuf(int type, char *msg)
{
    switch (type)
    {
        case GPE_LOG_TYPE_STDERR:
            fprintf(stderr, "%s\n", msg);
            break;
        case GPE_LOG_TYPE_STDOUT:
            fprintf(stdout, "%s\n", msg);
            break;
        default:
            printf("%s\n", msg);
            break;
    }
    return;
}

#define isprint(c) ((c) >= 0x20 /*SPC*/ && (c) < 0x7f /*DEL*/)

void
_gp_dumpBuf(int out, char *label, char *buf, int buflen)
{
    int  i        = 0;
    int  numBytes = 0;
    char line[17];
    char msg[84];
    char sp[32];
    char tmp[256];
    char hex[3];

    if (label != NULL)
    {
        (void)sprintf(tmp, "---------- %s (%d bytes) --------",
                      label, buflen);
        _writeBuf(out, tmp);
    }
    (void)memset(msg, 0, 84);
    (void)memset(sp, 0, 32);
    hex[2] = 0;
    sp[0] = ' ';

    if (buf != NULL)
    {
        for (i = 0; i < buflen; i++)
        {
            if (isprint(buf[i]))
            {
                line[i % 16] = buf[i];
            }
            else
            {
                line[i % 16] = '.';
            }
            (void)sprintf(sp, " %s", _toHexDigit(buf[i], hex));
            (void)strcat(msg, sp);
            if ((i % 16) == 15 || i == (buflen - 1))
            {
                line[i % 16 + 1] = '\0';
                for (numBytes = i % 16; numBytes < 15; numBytes++)
                {
                    (void)strcat(msg, "   ");
                }
                sprintf(sp, "      [%s]", line);
                strcat(msg, sp);
                _writeBuf(out, msg);
                (void)memset(msg, 0, 84);
                (void)memset(sp, 0, 32);
                sp[0] = ' ';
            }
        }
    }
    if (label != NULL)
    {
        _writeBuf(out, "-------- END --------");
    }
    return;
}


