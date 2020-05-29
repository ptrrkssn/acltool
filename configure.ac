AC_INIT([ACL Tool], [1.14], [pen@lysator.liu.se], [acltool], [https://github.com/ptrrkssn/acltool])
AC_PREREQ([2.67])

AC_CONFIG_AUX_DIR([aux])

AM_INIT_AUTOMAKE
AC_PROG_CC


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_ARG_WITH([readline], [
  AS_HELP_STRING([--with-readline],
    [support fancy command line editing @<:@default=check@:>@])],
  [], [with_readline=check])
          
READLINE=

AS_IF([test "x$with_readline" != xno], [
  case "x$with_readline" in
    /*)
      AC_SUBST([READLINE_CFLAGS], ["-I${with_readline}/include"])
      AC_SUBST([READLINE_LIBS], ["-L${with_readline}/lib -R${with_readline}/lib -lreadline -lncurses"])
      AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
      ;;
    *)
      PKG_CHECK_MODULES([READLINE], [readline], [
        AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
	echo "READLINE found via pkg-config"
      ], [			       
        AC_CHECK_LIB([readline], [readline], [
          AC_SUBST([READLINE_LIBS], ["-lreadline -lncurses"])
          AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
        ], [
          if test "x$with_readline" != xcheck; then
            AC_MSG_FAILURE([--with-readline was given, but test for readline failed])
          fi
        ], -lncurses)
      ])
      ;;
  esac
])


AC_ARG_WITH([libsmbclient], [
  AS_HELP_STRING([--with-libsmbclient],
    [support SMB via Samba libsmbclient @<:@default=check@:>@])],
  [],
  [with_libsmbclient=check])
          
LIBSMBCLIENT=

AS_IF([test "x$with_libsmbclient" != xno], [
  case "$with_libsmbclient" in
    /*)
      AC_SUBST([LIBSMBCLIENT_CFLAGS], ["-I${with_libsmbclient}/include"])
      AC_SUBST([LIBSMBCLIENT_LIBS], ["-L${with_libsmbclient}/lib -R${with_libsmbclient}/lib -lsmbclient"])
      AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if you have libsmbclient])
      ;;
    *)
      PKG_CHECK_MODULES([LIBSMBCLIENT], [libsmbclient], [
        AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if you have libsmbclient])
      ], [
        AC_CHECK_LIB([smbclient], [smbc_init], [
          AC_SUBST([LIBSMBCLIENT_LIBS], ["-lsmbclient"])
          AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if you have libsmbclient])
        ], [
          if test "x$with_libsmbclient" != xcheck; then
            AC_MSG_FAILURE([--with-libsmbclient was given, but test for libsmbclient failed])
          fi
        ])
      ])
      ;;
  esac
])

dnl AC_SEARCH_LIBS([smbc_init], [smbclient], [], [
dnl  AC_MSG_WARN([unable to find Samba libsmbclient])
dnl ])

AC_OUTPUT
