AUTOMAKE_OPTIONS = foreign
CFLAGS= @CFLAGS@ -I$(top_srcdir)/include -I${NZDIR}/include 
bin_PROGRAMS = dhsvr_ondmand dhclt tuxztca_svr tuxztca_clt 

dhsvr_ondmand_SOURCES = dhsvr_ondmand.c
dhsvr_ondmand_CFLAGS = ${CFLAGS}
dhsvr_ondmand_LDADD = ../lib/libtux_ztdh.la

tuxztca_svr_SOURCES = tuxztca_svr.c
tuxztca_svr_CFLAGS  = ${CFLAGS}
tuxztca_svr_LDADD   = ../lib/libtux_ztdh.la

dhclt_SOURCES = dhclt.c
dhclt_CFLAGS  = ${CFLAGS}
dhclt_LDADD   = ../lib/libtux_ztdh.la

tuxztca_clt_SOURCES = tuxztca_clt.c
tuxztca_clt_CFLAGS  = ${CFLAGS}
tuxztca_clt_LDADD   = ../lib/libtux_ztdh.la
