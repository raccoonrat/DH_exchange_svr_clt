/* test and set
 * low latency atomic counter
 * Author : yunhwang. Eva
 */
#ifndef _EVA_TAS_H
#define _EVA_TAS_H

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#if defined(__x86_64__)
#define ATOMICOPS_WORD_SUFFIX "q"
#else
#define ATOMICOPS_WORD_SUFFIX "l"
#endif
static inline size_t compare_and_swap(volatile size_t *p, size_t val_old, size_t val_new)
{
    char ret;
    __asm__ __volatile__("lock; cmpxchg" ATOMICOPS_WORD_SUFFIX " %3, %0; setz %1"
                         : "=m"(*p), "=q"(ret)
                         : "m"(*p), "r" (val_new), "a"(val_old)
                         : "memory");
    return (size_t)ret;
}
static inline size_t fetch_and_add(volatile size_t *p, size_t add)
{
    unsigned int ret;
    __asm__ __volatile__("lock; xaddl %0, %1"
                         :"=r" (ret), "=m" (*p)
                         : "0" (add), "m" (*p)
                         : "memory");
    return ret;
};
volatile size_t m_val_old=1;
volatile size_t g_uCount;
inline void try_continue(size_t val_old,size_t val_new)
{
    while(!compare_and_swap(&m_val_old,val_old,val_new)) {};
}

#if 0
const size_t cnt_num = 10000000;

void* sum_with_cas()
{
    int i=0;
    for( i=0; i< cnt_num; ++i)
    {
        try_continue(1,0);
        g_uCount += 1;
        try_continue(0,1);
    }
}

void* sum()
{
    sum_with_cas();
};

int main()
{
    int i=0;

    pthread_t* thread = (pthread_t*) malloc(10*sizeof( pthread_t));
    for( i=0; i<10; ++i)
    {
        pthread_create(&thread[i],NULL,(void*)sum,NULL);
    }
    for(i=0; i<10; ++i)
    {
        pthread_join(thread[i],NULL);
    }
    printf("g_uCount:%d/n",g_uCount);
}
#endif

#endif
