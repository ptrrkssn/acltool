/*
 * commands.c - ACL commands
 *
 * Copyright (c) 2020, Peter Eriksson <pen@lysator.liu.se>
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "commands.h"

#include "error.h"
#include "strings.h"


/* For 'argv0' and 'global_options' */
#include "acltool.h"


static COMMANDS global_commands;


int
cmd_init(COMMANDS *cmdlist) {
  if (!cmdlist)
    cmdlist = &global_commands;
  
  cmdlist->c = 0;
  return 0;
}


static int
_cmp_cmdname(const void *a, const void *b) {
  COMMAND *ca, *cb;

  ca = *(COMMAND **) a;
  cb = *(COMMAND **) b;

  return strcmp(ca->name, cb->name);
}


int
cmd_register(COMMANDS *cmdlist,
	     COMMAND **cpp) {
  if (!cpp)
    return -1;
  
  if (!cmdlist)
    cmdlist = &global_commands;
  
  for (; *cpp; ++cpp) {
    if (cmdlist->c >= MAXCMDS)
      return -1;
    
    cmdlist->v[cmdlist->c++] = *cpp;
  }

  qsort(&cmdlist->v[0], cmdlist->c, sizeof(cmdlist->v[0]), _cmp_cmdname);

  return 0;
}


int
cmd_help(COMMANDS *cmdlist,
	 const char *name,
	 FILE *fp,
	 int p_opts) {
  int nm, i;

  
  if (name) {
    COMMAND *cp = NULL;
    nm = 0;

    for (i = 0; i < cmdlist->c; i++) {
      cp = cmdlist->v[i];
      if (s_match(name, cp->name)) {
	if (!nm)
	  fprintf(fp, "COMMANDS:\n");
	fprintf(fp, "  %-20s\t%-30s\t%s\n", cp->name, cp->args, cp->help);
	if (p_opts)
	  opts_print(fp, global_options, cp->options, NULL);
	++nm;
      }
    }

    if (nm > 0)
      return -1;
  } 

  fprintf(fp, "COMMANDS:\n");
  for (i = 0; i < cmdlist->c; i++) {
    COMMAND *cp;
    
    cp = cmdlist->v[i];
    fprintf(fp, "  %-20s\t%-30s\t%s\n", cp->name, cp->args, cp->help);
  }
  
  return -1;
}



int
cmd_run(COMMANDS *cmdlist,
	int argc,
	char *argv[]) {
  int i, j, nm;
  COMMAND *scp;
  char *tmp_a0;

  
  if (!argv[0])
    return 0;
  
  if (strcmp(argv[0], "?") == 0)
    return cmd_help(cmdlist, argv[1], stdout, 0);
  else if (argv[1] && strcmp(argv[1], "?") == 0)
    return cmd_help(cmdlist, argv[0], stdout, 1);
  
  nm = 0;
  scp = NULL;
  for (i = 0; i < cmdlist->c; i++) {
    COMMAND *cp = cmdlist->v[i];
    
    if (s_match(argv[0], cp->name)) {
      scp = cp;
      ++nm;
    }
  }
  
  if (nm < 1)
    error(1, 0, "%s: Unknown command", argv[0]);

  if (nm > 1)
    error(1, 0, "%s: Nonunique command", argv[0]);

  tmp_a0 = argv[0];
  argv[0] = s_dup(scp->name);

  if (error_argv0)
    free(error_argv0);
  
  error_argv0 = s_dupcat(argv0, " ", argv[0], NULL);

  i = opts_parse_argv(argc, argv, global_options, scp->options, NULL);

  free(argv[0]);
  argv[0] = tmp_a0;
  
  if (i < 0)
    return i;
  for (j = 1; i < argc; i++, j++)
    argv[j] = argv[i];
  argv[j] = NULL;
  argc = j;

  return (*scp->handler)(argc, argv);
}


