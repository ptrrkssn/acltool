
AC_PREREQ([2.69])
AC_INIT([ACL Tool], [1.17.1], [pen@lysator.liu.se], [acltool], [https://github.com/ptrrkssn/acltool])

AC_CONFIG_SRCDIR([common.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR([build-aux])

AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h stdint.h stdlib.h string.h sys/acl.h sys/statvfs.h sys/time.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
dnl AC_FUNC_STRNLEN

AC_CHECK_FUNCS([acl getcwd memmove memset putenv regcomp strchr strdup strerror strndup strrchr strtol strtoul])


AC_ARG_WITH([readline],
  [AS_HELP_STRING([--with-readline],
    [support fancy command line editing (valid arguments: 'check', 'no', 'yes' or PATH) @<:@default=check@:>@])],
  [],
  [with_readline=check])

AC_ARG_WITH([libedit],
  [AS_HELP_STRING([--with-libedit],
    [support fancy command line editing (valid arguments: 'check', 'no', 'yes' or PATH) @<:@default=check@:>@])],
  [],
  [with_libedit=check])

echo "with:readline=$with_readline"
echo "with_libedit=$with_libedit"

if test "x$with_libedit" != xcheck -a "x$with_libedit" != xno; then
   if test "x$with_readline" = xcheck -o "x$with_readline" = xno; then
     with_readline=no
   else
     AC_MSG_ERROR([Only one of '--with-readline' and '--with-libedit' may be used])
   fi
fi
   
AS_IF([test "x$with_readline" != xno], [
  case "x$with_readline" in
    /*)
      AC_MSG_CHECKING(for READLINE in ${with_readline})
      if test -f "${with_readline}/include/readline/readline.h" -a -e "${with_readline}/lib/libreadline.so"; then
        AC_SUBST([READLINE_CFLAGS], ["-I${with_readline}/include"])
        AC_SUBST([READLINE_LIBS], ["-L${with_readline}/lib -R${with_readline}/lib -lreadline"])
        AC_DEFINE([HAVE_LIBREADLINE], [1], [Define if you have libreadline])
	AC_MSG_RESULT(yes)
      else
	AC_MSG_RESULT(no)
      fi
      ;;
    *)
      AC_CHECK_HEADERS([readline/readline.h])
      AC_SEARCH_LIBS([readline], [readline])
      if test "x$ac_cv_search_readline" = xno; then
        AC_SEARCH_LIBS([rl_set_prompt], [readline], [ 
          AC_SUBST([READLINE_LIBS], ["-ltermcap"])
	  ac_cv_search_readline=yes
        ], [], [-ltermcap])
      fi
      if test "x$ac_cv_search_readline" != xno -a "x$ac_cv_header_readline_readline_h" = xyes; then
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

AS_IF([test "x$with_readline" = xno], [
  AS_IF([test "x$with_libedit" != xno], [
    case "x$with_libedit" in
      /*)
        AC_MSG_CHECKING(for LIBEDIT in ${with_libedit})
        if test -f "${with_libedit}/include/histedit.h" -a -e "${with_libedit}/lib/libedit.so"; then
          AC_SUBST([LIBEDIT_CFLAGS], ["-I${with_libedit}/include"])
          AC_SUBST([LIBEDIT_LIBS], ["-L${with_libedit}/lib -R${with_libedit}/lib -ledit"])
          AC_DEFINE([HAVE_LIBEDIT], [1], [Define if you have libedit])
  	AC_MSG_RESULT(yes)
        else
  	AC_MSG_RESULT(no)
        fi
        ;;
      *)
        AC_CHECK_HEADERS([histedit.h])
        AC_SEARCH_LIBS([el_gets], [edit])
        if test "x$ac_cv_search_el_gets" = xno; then
          AC_SEARCH_LIBS([el_getc], [edit], [ 
            AC_SUBST([LIBEDIT_LIBS], ["-lcurses"])
  	  ac_cv_search_el_gets=yes
          ], [], [-lcurses])
        fi
        if test "x$ac_cv_search_el_gets" != xno -a "x$ac_cv_header_histedit_h" = xyes; then
          AC_DEFINE([HAVE_LIBEDIT], [1], [Define if you have libedit])
        else      
          PKG_CHECK_MODULES([LIBEDIT], [libedit], [
            AC_DEFINE([HAVE_LIBEDIT], [1], [Define if you have libedit])
          ], [			       
            if test "x$with_libedit" != xcheck; then
              AC_MSG_FAILURE([--with-libedit was given, but test for it failed])
            fi
          ])
        fi
        ;;
    esac
  ])
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
        PKG_CHECK_MODULES([LIBSMBCLIENT], [smbclient], [
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


AC_OUTPUT([Makefile pkgs/Makefile pkgs/Makefile.port pkgs/acltool.rb pkgs/pkginfo pkgs/acltool.spec pkgs/pkg-descr pkgs/build.sh])
