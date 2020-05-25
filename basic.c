/*
 * basic.c - Basic CLI commands
 *
 * Copyright (c) 2019-2020, Peter Eriksson <pen@lysator.liu.se>
 *
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#include "acltool.h"
#include "basic.h"

int
echo_cmd(int argc,
	 char **argv) {
  int i;

  
  for (i = 1; i < argc; i++) {
    if (i > 1)
      putchar(' ');
    fputs(argv[i], stdout);
  }
  putchar('\n');
  return 0;
}


int
pwd_cmd(int argc,
	char **argv) {
  char buf[2048];

#if 0
  if (!vfs_getcwd(buf, sizeof(buf)))
    error(1, errno, "Getting current directory");
#endif
  if (!vfs_fullpath(".", buf, sizeof(buf)))
    error(1, errno, "Getting current directory");
  
  puts(buf);
  return 0;
}


static int
_dirname_compare(const void *a, const void *b) {
  char *sa = * (char **) a;
  char *sb = * (char **) b;

  return strcmp(sa, sb);
}


int
dir_cmd(int argc,
	char **argv) {
  VFS_DIR *vdp;
  struct dirent *dep;
  int i, j;
  
  
  for (i = 1; i < argc || (i == 1 && argc == 1); i++) {
    SLIST *nlist;
    unsigned int n_files = 0;
    unsigned int n_dirs = 0;
    unsigned int n_others = 0;
    unsigned long long t_files = 0;
    
    
    vdp = vfs_opendir(argv[i]);
    if (!vdp)
      error(1, errno, "Opening directory");
    
    nlist = slist_new(1024);
    if (!nlist)
      error(1, errno, "Memory allocation failure");
    
    while ((dep = vfs_readdir(vdp)) != NULL)
      slist_add(nlist, dep->d_name);
    vfs_closedir(vdp);

    qsort(&nlist->v[0], nlist->c, sizeof(nlist->v[0]), _dirname_compare);

    if (config.f_verbose > 1) {
      char buf[2048];

      
      if (!vfs_fullpath(argv[i], buf, sizeof(buf)))
	error(1, errno, "Unable to get full directory name");
      
      printf("Directory of %s\n\n", buf);
    }
    
    for (j = 0; j < nlist->c; j++) {
      if (config.f_verbose) {
	char *path;
	struct stat sb;
	
	if (argv[i])
	  path = s_dupcat(argv[i], "/", nlist->v[j], NULL);
	else
	  path = s_dup(nlist->v[j]);
	
	if (vfs_lstat(path, &sb) < 0)
	  printf("%-20s  %-6s  %10s  %s\n", "?", "?", "", nlist->v[j]);
	else {
	  char tbuf[256];
	  struct tm *tp;

	  tp = localtime(&sb.st_mtime);
	  strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tp);
	  if (S_ISREG(sb.st_mode)) {
	    ++n_files;
	    t_files += sb.st_size;
	    
	    printf("%-20s  %-6s  %13llu  %s\n",
		   tbuf,
		   "",
		   (unsigned long long) sb.st_size,
		   nlist->v[j]);
	  } else if (S_ISDIR(sb.st_mode)) {
	    ++n_dirs;
	    
	    printf("%-20s  %-6s  %13llu  %s\n",
		   tbuf,
		   "<DIR>",
		   (unsigned long long) sb.st_size,
		   nlist->v[j]);
	  } else if (S_ISLNK(sb.st_mode)) {
	    char buf[2048];

	    ++n_others;
	    
	    if (readlink(path, buf, sizeof(buf)) < 0)
	      buf[0] = '\0';
	    printf("%-20s  %-6s  %13llu  %s -> %s\n",
		   tbuf,
		   "<LINK>",
		   (unsigned long long) sb.st_size,
		   nlist->v[j],
		   buf[0] ? buf : "?");
	  } else if (S_ISFIFO(sb.st_mode)) {
	    ++n_others;
	    
	    printf("%-20s  %-6s  %13s  %s\n",
		   tbuf,
		   "<FIFO>",
		   "",
		   nlist->v[j]);
	  } else if (S_ISSOCK(sb.st_mode)) {
	    ++n_others;
	    
	    printf("%-20s  %-6s  %13s  %s\n",
		   tbuf,
		   "<SOCK>",
		   "",
		   nlist->v[j]);
	  } else if (S_ISCHR(sb.st_mode)) {
	    ++n_others;
	    
	    printf("%-20s  %-6s  %13s  %s\n",
		   tbuf,
		   "<CHR>",
		   "",
		   nlist->v[j]);
	  } else if (S_ISBLK(sb.st_mode)) {
	    ++n_others;
	    
	    printf("%-20s  %-6s  %13s  %s\n",
		   tbuf,
		   "<BLK>",
		   "",
		   nlist->v[j]);
	  } else {
	    ++n_others;
	    
	    printf("%-20s  %-6s  %13s  %s\n",
		   tbuf,
		   "<?>",
		   "",
		   nlist->v[j]);
	  }
	}
      } else
	puts(nlist->v[j]);
    }
    slist_free(nlist);
    if (config.f_verbose > 1) {
      printf("\n%15u File%s    %18llu Byte%s\n",
	     n_files,
	     n_files == 1 ? " " : "s",
	     t_files,
	     t_files == 1 ? "" : "s");
      printf("%15u Director%s\n",
	     n_dirs,
	     n_dirs == 1 ? "y" : "ies");
    }
  }
  return 0;
}


int
cd_cmd(int argc,
       char **argv) {
  int i, rc;
  

  if (argc == 1) {
    char *homedir = getenv("HOME");

    if (!homedir)
      error(1, 0, "%s", "$HOME not set");
    
    rc = vfs_chdir(homedir);
    if (rc < 0)
      error(1, errno, "%s", homedir);

    return 0;
  }

  for (i = 1; i < argc; i++) {
    rc = vfs_chdir(argv[i]);
    if (rc < 0)
      error(1, errno, "%s", argv[i]);
  }
  
  if (config.f_verbose) {
    char buf[2048];

    if (!vfs_fullpath(".", buf, sizeof(buf)))
      error(1, errno, "Getting current directory");
    
    printf("New current directory: %s\n", buf);
  }
  
  return 0;
}


int
exit_cmd(int argc,
	 char **argv) {
  int ec = 0;

  
  if (argc > 1 && sscanf(argv[1], "%d", &ec) != 1)
    error(1, 0, "%s: Invalid exit code", argv[1]);

  exit(ec);
}

#if 0
size_t 
strnlen(const char *s,
	size_t maxlen) {
  ssize_t len = 0;

  if (!s)
    return 0;
  
  while (len < maxlen && *s != '\0')
    ++len;

  return len;
}
#endif


static int xattr_flags = 0;


static int
xattr_handler(const char *name,
	      const char *vs,
	      unsigned int type,
	      const void *svp,
	      void *dvp,
	      const char *a0) {
  if (!vs)
    return -1;

  if (strcmp(vs, "-") == 0) {
    xattr_flags = 0;
    return 0;
  }
  
  if (vfs_str2xattrflags(vs, &xattr_flags) < 0) {
    error(1, 0, "%s: Invalid extended attribute flags", vs);
    return -1;
  }

  return 0;
}



static OPTION xattr_options[] =
  {
   { "xattr-options", 'X', OPTS_TYPE_STR, xattr_handler, NULL, "Extended attribute options" },
   { NULL,            0,   0,             NULL,          NULL, NULL },
  };


int
listxattr_cmd(int argc,
	      char **argv) {
  int i;


  for (i = 1; i < argc; i++) {
    char buf[2048], *bp;
    ssize_t rc;
    int len;

    
    rc = vfs_listxattr(argv[i], buf, sizeof(buf), xattr_flags);
    if (rc < 0)
      error(1, errno, "%s: Getting Extended Attributes", argv[i]);

    if (config.f_verbose) {
      if (i > 1)
	putchar('\n');
      printf("Extended Attributes of %s:\n", argv[i]);
    } else
      printf("%s:\n", argv[i]);
    bp = buf;
    while (rc > 0) {
      len = strnlen(bp, rc);
      printf("  %.*s\n", len, bp);
      bp += len+1;
      rc -= len+1;
    }
  }
  
  return 0;
}


int
is_printable(char *buf,
	     size_t bufsize) {
  while (bufsize) {
    if (bufsize > 1 && !isprint(*buf))
      return 0;
    if (bufsize == 1 && *buf != '\0')
      return 0;
    ++buf;
    --bufsize;
  }

  return 1;
}

int
getxattr_cmd(int argc,
	      char **argv) {
  int i, j;


  if (argc < 3)
    error(1, 0, "Missing required arguments");
  
  if (config.f_verbose)
    printf("%s:\n", argv[1]);
  
  for (i = 2; i < argc; i++) {
    char buf[2048];
    ssize_t rc;
    int p_flag = 0;
    
    rc = vfs_getxattr(argv[1], argv[i], buf, sizeof(buf), xattr_flags);
    if (rc < 0)
      error(1, errno, "%s: %s: Getting Extended Attribute", argv[1], argv[i]);

    printf("  %s =", argv[i]);
    p_flag = is_printable(buf, rc);
    if (p_flag) {
      putchar(' ');
      putchar('"');
    }
    for (j = 0; j < rc; j++) {
      if (p_flag) {
	if (buf[j] == '"')
	  putchar('\\');
	putchar(buf[j]);
      } else
	printf(" %02x", buf[j]);
    }
    if (p_flag)
      putchar('"');
    putchar('\n');
  }
  
  return 0;
}

int
setxattr_cmd(int argc,
	      char **argv) {
  int i;


  if (argc < 3)
    error(1, 0, "Missing required arguments");
  
  for (i = 2; i < argc; i++) {
    int rc;
    char *vp = strchr(argv[i], '=');

    if (!vp)
      error(1, 0, "%s: Missing '=' delimiter", argv[i]);

    *vp++ = '\0';

    rc = vfs_setxattr(argv[1], argv[i], vp, strlen(vp)+1, xattr_flags);
    if (rc < 0)
      error(1, errno, "%s: %s: Setting Extended Attribute", argv[1], argv[i]);
    
    if (config.f_verbose)
      fprintf(stderr, "%s = \"%s\"\n", argv[i], vp);
  }
  
  return 0;
}

int
removexattr_cmd(int argc,
		char **argv) {
  int i;


  if (argc < 3)
    error(1, 0, "Missing required arguments");
  
  for (i = 2; i < argc; i++) {
    int rc;
    
    rc = vfs_removexattr(argv[1], argv[i], xattr_flags);
    if (rc < 0)
      error(1, errno, "%s: %s: Removing Extended Attribute", argv[1], argv[i]);

    if (config.f_verbose)
      printf("%s: Extended Attribute removed\n", argv[i]);
  }
  
  return 0;
}



COMMAND exit_command =
  { "exit-command", 	exit_cmd,	NULL, "[<code>]",	"Exit (with exit code)" };
COMMAND echo_command =
  { "echo-text", echo_cmd,		NULL, "[<str>]*",	"Print some text" };
COMMAND cd_command =
  { "change-directory", cd_cmd,		NULL, "[<path>]*",	"Change work directory" };
COMMAND dir_command =
  { "directory-listing", dir_cmd,	NULL, "[<path>]*",	"List directory" };
COMMAND pwd_command =
  { "print-work-directory", pwd_cmd,	NULL, "",		"Print work directory" };

COMMAND listxattr_command =
  { "list-xattr", listxattr_cmd,	xattr_options, "[<path>]*",			"List extended attributes" };
COMMAND getxattr_command =
  { "get-xattr", getxattr_cmd,		xattr_options, "<path>+ [<attr>]*",		"Get extended attributes" };
COMMAND setxattr_command =
  { "set-xattr", setxattr_cmd,		xattr_options, "<path>+ [<attr>=<val>]*",	"Set extended attributes" };
COMMAND removexattr_command =
  { "remove-xattr", removexattr_cmd,	xattr_options, "<path> [<attr>]*",		"Remove extended attributes" };


COMMAND *basic_commands[] =
  {
   &exit_command,
   &echo_command,
   &cd_command,
   &pwd_command,
   &dir_command,
   &listxattr_command,
   &getxattr_command,
   &setxattr_command,
   &removexattr_command,
   NULL,
  };

