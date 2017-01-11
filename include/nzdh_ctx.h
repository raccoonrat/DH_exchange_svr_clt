#ifndef NZSDKDH_CTX_H
#define NZSDKDH_CTX_H

#include "dhsocket.h"
#include "dhuser.h"

struct nz_dh_ctx
{
    dhsocket_t *socket;
    dhuser_t
};
typedef struct nz_dh_ctx nz_dh_ctx_t;

#endif

