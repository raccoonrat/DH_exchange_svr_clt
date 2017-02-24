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
int nzdh_KeyAgreePhase1(unsigned int lenBits, GPE_DH_CONTEXT_T **nzdh_ctx) {
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
    if (lenBits == 0 || nzdh_ctx == NULL) {
        goto err_ret;
    }

    if (alg != ZTCA_PALG_DH && alg != ZTCA_PALG_ECDH && alg != ZTCA_PALG_ECDHC) {
        return TZTCA_ERR_ARG;
    }
    /* allocate context */
    if ((context = (GPE_DH_CONTEXT_T *)malloc(sizeof(GPE_DH_CONTEXT_T))) == NULL) {
        return TZTCA_ERR_ARG;
    }
    (void)memset((char *)context, 0, sizeof(GPE_DH_CONTEXT_T));
    memset(&keyParams, 0, sizeof(keyParams));

    /* Fill in DH parameter, setup return of Prime numbers */
    keyParams.keyType = ZTCA_PUBKEY_PARAMS;
    keyParams.u.pubKeyParams.keyType = ZTCA_PKEY_DH_PARAMS;
    if (lenBits == sizeof(dhParamsBER128)) {
        dhParams->generator.data = zt_base_dhParamsBER128;
        dhParams->generator.len  = sizeof(zt_base_dhParamsBER128);
        dhParams->modulus.data   = zt_prime_dhParamsBER128;
        dhParams->modulus.len    = sizeof(zt_prime_dhParamsBER128);
    } else {
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
    if (err != ZTERR_OK) {
        err |= TZTCA_ERR_ASM_CTX_CREATE;
        goto err_ret;
    }
    TZTCA_PRN_UINT("    Param generation time: ", msec);

    err = ztca_CreatePubKeyCtx(NULL, key, alg, op, &cryptoCtx);
    if (err != ZTERR_OK) {
        err |= TZTCA_ERR_KE_CTX_CREATE;
        goto err_ret;
    }
    context->publicValueLen = sizeof(context->publicValue);

    err = ztca_DHGenPubValue(cryptoCtx, context->publicValue, &context->publicValueLen);
    if (err != ZTERR_OK) {
        err |= TZTCA_ERR_KE_PUB_VAL;
        goto err_ret;
    } else {
        context->cryptoCtx = cryptoCtx;
        *nzdh_ctx = context;
    }
    ztca_DestroyKey(key, FALSE);

    return ZTERR_OK;
err_ret:
    if (context != NULL) {
        free(context);
        context = NULL;
    }
    return err;
}


unsigned char *
nzdh_AllocAgreedSecretKey(unsigned int *sizep) {
    unsigned char *tmp = (unsigned char *)calloc(1,sizeof(zt_base_dhParamsBER128));
    if (tmp == NULL) {
        *sizep = 0;
    } else {
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
                        unsigned char *agreedSecret, unsigned int *agreedSecretLen, GPE_DH_CONTEXT_T  *context ) {
    zterr err;
    ztcaPubKeyAlgType alg = ZTCA_PALG_DH;
    ztcaCryptoOpType op = ZTCA_EXCHANGE;
    unsigned int plen, len;


    struct timeval tv, tv_new;
    unsigned long msec;

    /* Check input arguments */
    if (context == NULL ||
        agreedSecret == NULL || agreedSecretLen == NULL) {
        return TZTCA_ERR_ARG;
    }

    if (context->agreedSecretLen == 0) {
        unsigned char *tmp = NULL;
        context->agreedSecretLen = sizeof(context->agreedSecret);
        TZTCA_START_TIME(tv);
        err = ztca_DHGenSharedSecret(context->cryptoCtx, pub_remote.data, pub_remote.len,
                                     context->agreedSecret, &context->agreedSecretLen);
        TZTCA_STOP_TIME_MSEC(tv, tv_new, msec);
        if (err != ZTERR_OK) {
            context->agreedSecretLen = 0;
            err |= TZTCA_ERR_KE_SESS_KEY;
            TZTCA_PRN_UINT("    Shared secret generation failed time: ", msec);
            goto err_ret;
        } else {
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


void nzdh_destroy(ztcaCryptoCtx *cryptoCtx, ztcaData pub, ztcaData sess) {
    ztca_FreeData(&sess, FALSE);
    ztca_FreeData(&pub, FALSE);
    ztca_DestroyCryptoCtx(cryptoCtx);

    return ;
}


static char *
_toHexDigit(unsigned char c, char *ret) {
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
_writeBuf(int type, char *msg) {
    switch (type) {
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
_gp_dumpBuf(int out, char *label, char *buf, int buflen) {
    int  i        = 0;
    int  numBytes = 0;
    char line[17];
    char msg[84];
    char sp[32];
    char tmp[256];
    char hex[3];

    if (label != NULL) {
        (void)sprintf(tmp, "---------- %s (%d bytes) --------",
                      label, buflen);
        _writeBuf(out, tmp);
    }
    (void)memset(msg, 0, 84);
    (void)memset(sp, 0, 32);
    hex[2] = 0;
    sp[0] = ' ';

    if (buf != NULL) {
        for (i = 0; i < buflen; i++) {
            if (isprint(buf[i])) {
                line[i % 16] = buf[i];
            } else {
                line[i % 16] = '.';
            }
            (void)sprintf(sp, " %s", _toHexDigit(buf[i], hex));
            (void)strcat(msg, sp);
            if ((i % 16) == 15 || i == (buflen - 1)) {
                line[i % 16 + 1] = '\0';
                for (numBytes = i % 16; numBytes < 15; numBytes++) {
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
    if (label != NULL) {
        _writeBuf(out, "-------- END --------");
    }
    return;
}


