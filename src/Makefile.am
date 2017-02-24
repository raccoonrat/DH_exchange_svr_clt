AUTOMAKE_OPTIONS = foreign
CFLAGS= @CFLAGS@ -I$(top_srcdir)/include -I${NZDIR}/include -DDEBUG
#bin_PROGRAMS = dhsvr_ondmand dhclt tuxztca_svr tuxztca_clt nzsdk_svr_ev nzsdk_clt_ev
bin_PROGRAMS = nzsdk_svr_ev nzsdk_clt_ev

#dhsvr_ondmand_SOURCES = dhsvr_ondmand.c
#dhsvr_ondmand_CFLAGS = ${CFLAGS}
#dhsvr_ondmand_LDADD = ../lib/libtux_ztdh.la
#
#tuxztca_svr_SOURCES = tuxztca_svr.c
#tuxztca_svr_CFLAGS  = ${CFLAGS}
#tuxztca_svr_LDADD   = ../lib/libtux_ztdh.la
#
#dhclt_SOURCES = dhclt.c
#dhclt_CFLAGS  = ${CFLAGS}
#dhclt_LDADD   = ../lib/libtux_ztdh.la
#
#tuxztca_clt_SOURCES = tuxztca_clt.c
#tuxztca_clt_CFLAGS  = ${CFLAGS}
#tuxztca_clt_LDADD   = ../lib/libtux_ztdh.la

nzsdk_svr_ev_SOURCES = nzsdk_svr_ev.c workqueue.c
nzsdk_svr_ev_CFLAGS = ${CFLAGS}
#nzsdk_svr_ev_LDADD = ../lib/libtux_ztdh.la -levent -lpthread
nzsdk_svr_ev_LDADD = ../lib/libtux_ztdh.la -levent_core -levent_extra -lpthread -levent_pthreads

nzsdk_clt_ev_SOURCES = nzsdk_clt_ev.c workqueue.c
nzsdk_clt_ev_CFLAGS = ${CFLAGS}
#nzsdk_clt_ev_LDADD = ../lib/libtux_ztdh.la -levent -lpthread
nzsdk_clt_ev_LDADD = ../lib/libtux_ztdh.la -levent_core -levent_extra -lpthread -levent_pthreads

