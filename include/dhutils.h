#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <stdlib.h>
#include <gmp.h>
#include "hexString.h"

typedef unsigned char byte;

void*           new(int,size_t);
void            delete(void*, size_t);
void            s_memclr(void*, size_t);
char*           hash(const char*);
void            sign(const char*, byte*, unsigned int*);
int             verify(const char*, byte*, unsigned int);
void            fastExponent(mpz_t,mpz_t,mpz_t,mpz_t);
int             constantVerify(const byte*, const byte*);
int             verifySafePrime(mpz_t,int);

void            diewitherror(char *);

#endif
