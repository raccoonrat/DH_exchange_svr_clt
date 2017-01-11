#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([nzsdk_dh], [0.1], [yunao@gmai.com])
AC_CONFIG_SRCDIR([lib/hexString.c])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE
# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
LT_INIT
AM_CONDITIONAL([NZDIR], [test -z "$NZDIR"])
AS_IF([test  -z "$NZDIR"],
      [AC_MSG_ERROR([NZDIR required but not found!!!])
      ])


# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcore12':
AC_CHECK_LIB([core12], [main])
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lipgo':
AC_CHECK_LIB([ipgo], [main])
# FIXME: Replace `main' with a function in `-lirc':
AC_CHECK_LIB([irc], [main])
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-lnls12':
AC_CHECK_LIB([nls12], [main])
# FIXME: Replace `main' with a function in `-lnnzst12':
AC_CHECK_LIB([nnzst12], [main])
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])
# FIXME: Replace `main' with a function in `-lrt':
AC_CHECK_LIB([rt], [main])
# FIXME: Replace `main' with a function in `-lunls12':
AC_CHECK_LIB([unls12], [main])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero floor gettimeofday memset munmap socket strerror])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 src/Makefile])
AC_OUTPUT
