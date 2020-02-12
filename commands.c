/*
 * aclcmds.c - ACL commands
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "misc.h"
#include "strings.h"
#include "commands.h"


void
cmd_init(COMMANDS *cp) {
  cp->cc = 0;
}


int
cmd_register(COMMANDS *cp,
	     int cc,
	     COMMAND cv[]) {
  int i;

  
  for (i = 0; cc ? i < cc : cv[i].name != NULL; i++) {
    if (cp->cc >= CMDS_MAX)
      return -1;

    cp->cv[cp->cc++] = &cv[i];
  }

  return cp->cc;
}


int
_cmd_help(COMMANDS *cmds,
	  const char *name) {
  int i, nm;
  COMMAND *cp;

  
  puts("COMMANDS:");
  
  if (name) {
    cp = NULL;
    nm = 0;

    for (i = 0; i < cmds->cc; i++) {
      if (s_match(name, cmds->cv[i]->name)) {
	cp = cmds->cv[i];
	printf("  %-20s\t%-30s\t%s\n", cp->name, cp->args, cp->help);
	++nm;
      }
    }
    
    if (nm < 1) {
      fprintf(stderr, "%s: No such command\n", name);
      return -1;
    }
    
  } else {
    
    for (i = 0; i < cmds->cc; i++) {
      cp = cmds->cv[i];
      printf("  %-20s\t%-30s\t%s\n", cp->name, cp->args, cp->help);
    }
  }
  
  return 0;
}


int
cmd_run(COMMANDS *cmds,
	int argc,
	char *argv[],
	void *vp) {
  int i, nm;
  COMMAND *scp;


  if (!argv[0])
    return 0;
  
  if (strcmp(argv[0], "?") == 0)
    return _cmd_help(cmds, argv[1]);
  else if (argv[1] && strcmp(argv[1], "?") == 0)
    return _cmd_help(cmds, argv[0]);
  
  nm = 0;
  scp = NULL;
  for (i = 0; i < cmds->cc; i++) {
    COMMAND *cp = cmds->cv[i];
    
    if (s_match(argv[0], cp->name)) {
      scp = cp;
      ++nm;
    }
  }
  
  if (nm < 1) {
    fprintf(stderr, "Error: %s: No such command\n", argv[0]);
    return -1;
  }

  if (nm > 1) {
    fprintf(stderr, "Error: %s: Matches multiple commands\n", argv[0]);
    return -1;
  }

  
  return (*scp->handler)(argc, argv, vp);
}

