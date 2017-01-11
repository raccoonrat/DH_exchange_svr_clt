#ifndef TZTCA_H
#define TZTCA_H

#include <sys/time.h>

#include <ztca.h>

#define PASSED     0

#define RNG_BUFF_SIZE     1024

#define ZTERR_MASK         0x3FF
#define ZTERR_OR_MASK     (0xFFFF ^ ZTERR_MASK)
#define TZTCA_ERR_BASE     0
#define TZTCA_ERR_BASE_OFF 10


#define TZTCA_ERR_ARG                  (TZTCA_ERR_BASE + 1) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_INIT                 (TZTCA_ERR_BASE + 2) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_SHUTDOWN             (TZTCA_ERR_BASE + 3) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_RNG_SEED_FAILED      (TZTCA_ERR_BASE + 4) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_RNG_INIT_FAILED      (TZTCA_ERR_BASE + 4) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_RNG_GET_RAND_FAILED  (TZTCA_ERR_BASE + 6) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_DST_CREATE_CTX       (TZTCA_ERR_BASE + 7) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_DST_INIT             (TZTCA_ERR_BASE + 8) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_DST_UPDATE           (TZTCA_ERR_BASE + 9) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_DST_FINISH           (TZTCA_ERR_BASE + 10) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_DST_DESTROY          (TZTCA_ERR_BASE + 11) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_KEY_CREATE       (TZTCA_ERR_BASE + 12) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_CTX_CREATE       (TZTCA_ERR_BASE + 13) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_ENCRYPT          (TZTCA_ERR_BASE + 14) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_DECRYPT          (TZTCA_ERR_BASE + 15) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_SIGN             (TZTCA_ERR_BASE + 16) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_VERIFY           (TZTCA_ERR_BASE + 17) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_VERIFY_RES       (TZTCA_ERR_BASE + 18) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_ASM_TEST_INIT        (TZTCA_ERR_BASE + 19) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_KE_KEY_GEN           (TZTCA_ERR_BASE + 20) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_KE_CTX_CREATE        (TZTCA_ERR_BASE + 21) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_KE_PUB_VAL           (TZTCA_ERR_BASE + 22) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_KE_SESS_KEY          (TZTCA_ERR_BASE + 23) << TZTCA_ERR_BASE_OFF
#define TZTCA_ERR_KE_KEY_MISMATCH      (TZTCA_ERR_BASE + 24) << TZTCA_ERR_BASE_OFF
/* #define TZTCA_ERR_      (TZTCA_ERR_BASE + ) << TZTCA_ERR_BASE_OFF */
/* #define TZTCA_ERR_      (TZTCA_ERR_BASE + ) << TZTCA_ERR_BASE_OFF */

typedef struct tztca_ErrToStrStr
{
    unsigned int err;
    char *buff;
} tztca_ErrToStrStr;

#define ERR(errCode, errStr) { errCode >> TZTCA_ERR_BASE_OFF, errStr}

const tztca_ErrToStrStr tztca_errArr[] =
{
    ERR(TZTCA_ERR_BASE, "OK"),
    ERR(TZTCA_ERR_ARG, "Bad function argument"),
    ERR(TZTCA_ERR_INIT, "Failed to init ztca"),
    ERR(TZTCA_ERR_SHUTDOWN, "Failed to shutdown ztca"),
    ERR(TZTCA_ERR_RNG_SEED_FAILED, "Failed to seed RNG"),
    ERR(TZTCA_ERR_RNG_INIT_FAILED, "Failed to init RNG"),
    ERR(TZTCA_ERR_RNG_GET_RAND_FAILED, "Failed to get random"),
    ERR(TZTCA_ERR_DST_CREATE_CTX, "Failed to create digest context"),
    ERR(TZTCA_ERR_DST_INIT, "Failed to init digest context"),
    ERR(TZTCA_ERR_DST_UPDATE, "Filed to update digest context"),
    ERR(TZTCA_ERR_DST_FINISH, "Failed to finish digest context"),
    ERR(TZTCA_ERR_DST_DESTROY, "Failed to destroy digest context"),
    ERR(TZTCA_ERR_ASM_KEY_CREATE, "Failed to generate the asym key"),
    ERR(TZTCA_ERR_ASM_CTX_CREATE, "Failed to init the asym ctx"),
    ERR(TZTCA_ERR_ASM_TEST_INIT, "Failed to init the asym test"),
    ERR(TZTCA_ERR_ASM_ENCRYPT, "Failed to encrypt with asym crypto ctx"),
    ERR(TZTCA_ERR_ASM_DECRYPT, "Failed to decrypt with asym crypto ctx"),
    ERR(TZTCA_ERR_ASM_SIGN, "Failed to sign with asym crypto ctx"),
    ERR(TZTCA_ERR_ASM_VERIFY, "Failed to verify with asym crypto ctx"),
    ERR(TZTCA_ERR_ASM_VERIFY_RES, "Failed to verify results"),
    ERR(TZTCA_ERR_KE_KEY_GEN, "Failed to generate the key"),
    ERR(TZTCA_ERR_KE_CTX_CREATE, "Failed to create context"),
    ERR(TZTCA_ERR_KE_PUB_VAL, "Failed to create pub value"),
    ERR(TZTCA_ERR_KE_SESS_KEY, "Failed to create sess key"),
    ERR(TZTCA_ERR_KE_KEY_MISMATCH, "KE key missmatch")
};

#ifdef DEBUG
#define TZTCA_PRN_RES(str, code) \
    printf("%s - %s(zterr: %d)\n", str, \
           tztca_errArr[code >> TZTCA_ERR_BASE_OFF].buff, \
           code & ZTERR_MASK)

#define TZTCA_PRN_RES_STR(str, param1, code)                              \
    printf("%s(%s) - %s(zterr: %d)\n", str, param1, \
           tztca_errArr[code >> TZTCA_ERR_BASE_OFF].buff,   \
           code & ZTERR_MASK)

#define TZTCA_PRN_STAT(str, code) \
    printf("%s - %s\n", str, (code & ZTERR_OR_MASK) ? "FAILED" : "passed")

#define TZTCA_PRN_UINT(str, code) \
    printf("%s %lu\n", str, code)

#define TZTCA_START_TIME(tp) \
    gettimeofday(&tp, NULL);

#define TZTCA_STOP_TIME_MSEC(tp, tp_new, msec)   \
    gettimeofday(&tp_new, NULL); \
    msec = (tp_new.tv_sec - tp.tv_sec) *1000000 + tp_new.tv_usec - tp.tv_usec;
#else
#define TZTCA_PRN_RES(str, code) /**/
#define TZTCA_PRN_RES_STR(str, param1, code) /**/
#define TZTCA_PRN_STAT(str, code) /**/
#define TZTCA_PRN_UINT(str, code) /**/
#define TZTCA_START_TIME(tp) /**/
#define TZTCA_STOP_TIME_MSEC /* */
#endif

typedef struct rsaTestCfgStr
{
    int keySize;
    ztcaData key;
} rsaTestCfg;

typedef struct ecTestCfgStr
{
} ecTestCfg;

typedef struct dhTestCfgStr
{
} dhTestCfg;

typedef struct dsaTestCfgStr
{
    unsigned int primeBits;
} dsaTestCfg;

typedef struct asymTestConfigStr
{
    ztcaKeyType type;
    ztcaPubKeyAlgType alg;
    ztcaCryptoOpType op;
    int numOps;
    int reuseKeyIndex;
    int reuseOutAsInBuffIndex;
    int reuseOutAsOutBuffIndex;
    union
    {
        rsaTestCfg rsaCfg;
        dhTestCfg  dhCfg;
        dsaTestCfg dsaCfg;
        ecTestCfg  ecCfg;
    } u;
    ztcaData in;
    ztcaData out;
    ztcaKey *key;
} asymTestConfig;

#endif
