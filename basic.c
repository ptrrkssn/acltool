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
cmd_echo(int argc,
	 char **argv,
	 void *vp) {
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
cmd_pwd(int argc,
	char **argv,
	void *vp) {
  char buf[2048];

  if (getcwd(buf, sizeof(buf)))
    puts(buf);

  return 0;
}

int
cmd_cd(int argc,
       char **argv,
       void *vp) {
  int i, rc;
  

  if (argc == 1) {
    char *homedir = getenv("HOME");

    if (!homedir) {
      fprintf(stderr, "%s: Error: Unable to read HOME environment\n",
	      argv0);
      return 1;
    }
    
    rc = chdir(homedir);
    if (rc < 0) {
      fprintf(stderr, "%s: Error: %s: Changing directory: %s\n",
	      argv[0], homedir, strerror(errno));
      return 1;
    }

    return 0;
  }

  for (i = 1; i < argc; i++) {
    rc = chdir(argv[i]);
    if (rc < 0) {
      fprintf(stderr, "%s: Error: %s: Changing directory: %s\n",
	      argv[0], argv[i], strerror(errno));
      return 1;
    }
  }
  
  return 0;
}


int
cmd_exit(int argc,
	 char **argv,
	 void *vp) {
  int ec = 0;

  
  if (argc > 1) {
    if (sscanf(argv[1], "%d", &ec) != 1) {
      fprintf(stderr, "%s: Error: %s: Invalid exit code\n", argv[0], argv[1]);
      return -1;
    }
  }

  exit(ec);
}





COMMAND basic_commands[] = {
  { "exit", 	"[<code>]",	cmd_exit,	"Exit (with exit code)" },
  { "echo", 	"[<str>]*",	cmd_echo,	"Print some text" },
  { "cd", 	"[<path>]*",	cmd_cd,		"Change working directory" },
  { "pwd", 	"",		cmd_pwd,	"Print working directory" },
  { NULL,	NULL,		NULL,		NULL },
};

