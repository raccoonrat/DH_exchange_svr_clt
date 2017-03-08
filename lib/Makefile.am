#NZDIR = @NZDIR@
#EVDIR = @EVDIR@

lib_LTLIBRARIES= libtux_ztdh.la

libtux_ztdh_la_SOURCES = tux_ztdh.c dhsocket.c dhutils.c  hexString.c 
libtux_ztdh_la_CFLAGS = -I$(top_srcdir)/include -I${NZDIR}/include 
libtux_ztdh_la_LIBADD = -lm -lrt -lpthread -ldl -L${NZDIR}/lib -lnnzst12 -lcore12 -lnls12 -lunls12 -lirc -lipgo
libtux_ztdh_la_LDFLAGS = -version-info 1:0:1

