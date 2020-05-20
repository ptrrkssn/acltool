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
#include <errno.h>

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

  if (!vfs_getcwd(buf, sizeof(buf)))
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

    for (j = 0; j < nlist->c; j++) {
      if (config.f_verbose) {
	char *path;
	struct stat sb;
	
	if (argv[i])
	  path = strxcat(argv[i], "/", nlist->v[j], NULL);
	else
	  path = strdup(nlist->v[j]);
	
	if (vfs_lstat(path, &sb) < 0)
	  printf("%-20s  %-6s  %10s  %s\n", "?", "?", "", nlist->v[j]);
	else {
	  char tbuf[256];
	  struct tm *tp;

	  tp = localtime(&sb.st_mtime);
	  strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tp);
	  if (S_ISREG(sb.st_mode))
	    printf("%-20s  %-6s  %10llu  %s\n",
		   tbuf,
		   "",
		   (unsigned long long) sb.st_size,
		   nlist->v[j]);
	  else if (S_ISDIR(sb.st_mode))
	    printf("%-20s  %-6s  %10s  %s\n",
		   tbuf,
		   "<DIR>",
		   "",
		   nlist->v[j]);
	  else if (S_ISLNK(sb.st_mode)) {
	    char buf[2048];

	    buf[0] = '\0';
	    (void) readlink(path, buf, sizeof(buf));
	    
	    printf("%-20s  %-6s  %10s  %s -> %s\n",
		   tbuf,
		   "<LINK>",
		   "",
		   nlist->v[j],
		   buf[0] ? buf : "?");
	  } else if (S_ISFIFO(sb.st_mode))
	    printf("%-20s  %-6s  %10s  %s\n",
		   tbuf,
		   "<FIFO>",
		   "",
		   nlist->v[j]);
	  else if (S_ISSOCK(sb.st_mode))
	    printf("%-20s  %-6s  %10s  %s\n",
		   tbuf,
		   "<SOCK>",
		   "",
		   nlist->v[j]);
	  else if (S_ISCHR(sb.st_mode))
	    printf("%-20s  %-6s  %10s  %s\n",
		   tbuf,
		   "<CHR>",
		   "",
		   nlist->v[j]);
	  else if (S_ISBLK(sb.st_mode))
	    printf("%-20s  %-6s  %10s  %s\n",
		   tbuf,
		   "<BLK>",
		   "",
		   nlist->v[j]);
	  else
	    printf("%-20s  %-6s  %-10s  %s\n",
		   tbuf,
		   "<?>",
		   "",
		   nlist->v[j]);
	}
      } else
	puts(nlist->v[j]);
    }
    slist_free(nlist);
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



COMMAND exit_command =
  { "exit-command", 	exit_cmd,	NULL, "[<code>]",	"Exit (with exit code)" };

COMMAND echo_command =
  { "echo-text", 	echo_cmd,	NULL, "[<str>]*",	"Print some text" };

COMMAND cd_command =
  { "change-directory",  cd_cmd,		NULL, "[<path>]*",	"Change working directory" };

COMMAND dir_command =
  { "directory-listing",    dir_cmd,		NULL, "[<path>]*",	"List directory" };

COMMAND pwd_command =
  { "print-working-directory", 	pwd_cmd,	NULL, "",		"Print working directory" };


COMMAND *basic_commands[] =
  {
   &exit_command,
   &echo_command,
   &cd_command,
   &pwd_command,
   &dir_command,
   NULL,
  };

