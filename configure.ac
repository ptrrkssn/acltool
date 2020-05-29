AC_INIT([ACL Tool], [1.14], [pen@lysator.liu.se], [acltool], [https://github.com/ptrrkssn/acltool])
AC_PREREQ([2.67])

AC_CONFIG_AUX_DIR([aux])

AM_INIT_AUTOMAKE
AC_PROG_CC


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])


AC_ARG_WITH([readline],
  [AS_HELP_STRING([--with-readline],
    [support fancy command line editing (valid arguments: 'check', 'no', 'yes' or PATH) @<:@default=check@:>@])],
  [],
  [with_readline=check])
          
AS_IF([test "x$with_readline" != xno], [
  case "x$with_readline" in
    /*)
      AC_MSG_CHECKING(for READLINE in ${with_readline})
      if test -f "${with_readline}/include/readline/readline.h" -a -e "${with_readline}/lib/libreadline.so"; then
        AC_SUBST([READLINE_CFLAGS], ["-I${with_readline}/include"])
        AC_SUBST([READLINE_LIBS], ["-L${with_readline}/lib -R${with_readline}/lib -lreadline -lncurses"])
        AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
	AC_MSG_RESULT(yes)
      else
	AC_MSG_RESULT(no)
      fi
      ;;
    *)
      AC_CHECK_HEADERS([readline/readline.h])
      AC_CHECK_LIB([readline], [readline], [ 
        AC_SUBST([READLINE_LIBS], ["-lreadline -lncurses"])
      ], [], -lncurses)
      if test "x$ac_cv_lib_readline_readline" = xyes -a "x$ac_cv_header_readline_readline.h" = xyes; then 
	AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
      else
        PKG_CHECK_MODULES([READLINE], [readline], [
	  # Hack to fix incorrect path in FreeBSD "pkg-config --cflags" (sigh)
          readline_incdir="`pkg-config --variable=includedir readline`"
          AC_SUBST([READLINE_CFLAGS], ["-I${readline_incdir}"])
	  
          AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
        ], [			       
          if test "x$with_readline" != xcheck; then
            AC_MSG_FAILURE([--with-readline was given, but test for readline failed])
          fi
        ])
      fi
      ;;
  esac
])


AC_ARG_WITH([libsmbclient],
  [AS_HELP_STRING([--with-libsmbclient],
    [support SMB via Samba libsmbclient (valid arguments: 'check', 'no', 'yes' or PATH) @<:@default=check@:>@])],
  [],
  [with_libsmbclient=check])
          
AS_IF([test "x$with_libsmbclient" != xno], [
  case "$with_libsmbclient" in
    /*)
      AC_MSG_CHECKING(for LIBSMBCLIENT in ${with_libsmbclient})
      if test -f "${with_libsmbclient}/include/libsmbclient.h" -a -e "${with_libsmbclient}/lib/libsmbclient.so" ; then
        AC_SUBST([LIBSMBCLIENT_CFLAGS], ["-I${with_libsmbclient}/include"])
        AC_SUBST([LIBSMBCLIENT_LIBS], ["-L${with_libsmbclient}/lib -R${with_libsmbclient}/lib -lsmbclient"])
        AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if you have libsmbclient])
        AC_MSG_RESULT(yes)
      else
        AC_MSG_RESULT(no)
      fi
      ;;
    *)
      AC_CHECK_HEADERS([libsmbclient.h])
      AC_CHECK_LIB([smbclient], [smbc_init], [
        AC_SUBST([LIBSMBCLIENT_LIBS], ["-lsmbclient"])
      ], [])
      if test "x$ac_cv_lib_libsmbclient_smbc_init" = xyes -a "x$ac_cv_header_libsmbclient.h" = xyes; then 
        AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if you have libsmbclient])
      else
        PKG_CHECK_MODULES([LIBSMBCLIENT], [libsmbclient], [
          AC_DEFINE([HAVE_LIBSMBCLIENT], [1], [Define if you have libsmbclient])
        ], [
          if test "x$with_libsmbclient" != xcheck; then
            AC_MSG_FAILURE([--with-libsmbclient was given, but test for libsmbclient failed])
          fi
        ])
      fi
      ;;
  esac
])


AC_OUTPUT
