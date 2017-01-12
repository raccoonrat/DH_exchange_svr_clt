#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <stdlib.h>
#ifdef __GMPZ_DEF__
#include <gmp.h>
#endif
#include "hexString.h"

typedef unsigned char byte;

void*           new(int,size_t);
void            delete(void*, size_t);
void            s_memclr(void*, size_t);
int             constantVerify(const byte*, const byte*);
void            diewitherror(char *);

#ifdef __GMPZ_DEF__
char*           hash(const char*);
void            sign(const char*, byte*, unsigned int*);
int             verify(const char*, byte*, unsigned int);
void            fastExponent(mpz_t,mpz_t,mpz_t,mpz_t);
int             verifySafePrime(mpz_t,int);
#endif


#endif
