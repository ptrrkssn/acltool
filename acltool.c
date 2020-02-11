/*
 * acltool.c
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
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ftw.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "argv.h"
#include "misc.h"
#include "commands.h"

#include "acltool.h"




#define SHORT_OPTIONS "hndvrS:D:"

struct option long_options[] =
  {
   { "help",      no_argument,       NULL, 'h' },
   { "debug",     optional_argument, NULL, 'D' },
   { "verbose",   optional_argument, NULL, 'v' },
   { "recurse",   optional_argument, NULL, 'r' },
   { "no-depth",  no_argument,       NULL, 'd' },
   { "no-update", no_argument,       NULL, 'n' },
   { "style",     required_argument, NULL, 'S' },
   { NULL,        0,                 NULL, 0 },
};


int
str2style(const char *str,
	  ACL_STYLE *sp) {
  if (!str || !*str)
    return 0;
  
  if (strcasecmp(str, "default") == 0)
    *sp = ACL_STYLE_DEFAULT;
  else if (strcasecmp(str, "brief") == 0)
    *sp = ACL_STYLE_BRIEF;
  else if (strcasecmp(str, "csv") == 0)
    *sp = ACL_STYLE_CSV;
  else if (strcasecmp(str, "solaris") == 0)
    *sp = ACL_STYLE_SOLARIS;
  else
    return -1;

  return 1;
}

const char *
style2str(ACL_STYLE s) {
  switch (s) {
  case ACL_STYLE_DEFAULT:
    return "Default";
  case ACL_STYLE_BRIEF:
    return "Brief";
  case ACL_STYLE_CSV:
    return "CSV";
  case ACL_STYLE_SOLARIS:
    return "Solaris";
  }

  return NULL;
}

	  

int
option_set_short(CONFIG *cfgp,
		 int f,
		 const char *val) {
  switch (f) {
  case 'h':
    break;
    
  case 'n':
    cfgp->f_noupdate = 1;
    break;

  case 'd':
    cfgp->f_nodepth = 1;
    break;

  case 'D':
    if (val) {
      if (sscanf(val, "%d", &cfgp->f_debug) != 1) {
	fprintf(stderr, "%s: Error: %s: Invalid debug level\n", argv0, val);
	return -1;
      }
    } else
      cfgp->f_debug++;
    break;
    
  case 'S':
    if (val) {
      if (sscanf(val, "%d", &cfgp->f_style) != 1 && str2style(val, &cfgp->f_style) != 1) {
	fprintf(stderr, "%s: Error: %s: Invalid ACL style\n", argv0, val);
	return -1;
      }
    } else
      cfgp->f_style++;
    break;
    
  case 'v':
    if (val) {
      if (sscanf(val, "%d", &cfgp->f_verbose) != 1) {
	fprintf(stderr, "%s: Error: %s: Invalid verbose level\n", argv0, val);
	return -1;
      }
    } else
      cfgp->f_verbose++;
    break;
    
  case 'r':
    if (val) {
      if (sscanf(val, "%d", &cfgp->f_recurse) != 1) {
	fprintf(stderr, "%s: Error: %s: Invalid recurse level\n", argv0, val);
	return -1;
      }
    } else
      cfgp->f_recurse++;
    break;
    
  default:
    return -1;
  }

  return 0;
}

int
option_set_long(CONFIG *cfgp,
		const char *name,
		const char *val) {
  int i;
  struct option *op = NULL;
  
  for (i = 0; !op && long_options[i].name; i++) {
    if (strcmp(long_options[i].name, name) == 0) {
      if (op)
	return -1;
      op = &long_options[i];
    }
  }
  if (!op)
    return -1;

  return option_set_short(cfgp, op->val, val);
}


char *argv0;
CONFIG d_cfg = { 0, 0, 0, 0, 0, 0 };

extern COMMAND cmdv[];



char *
my_var_handler(const char *esc,
	       void *xtra)
{
    printf("Parsing var [%s]\n", esc ? esc : "<null>");

    if (strcmp(esc, "P") == 0 || strcmp(esc, "phone") == 0)
	return s_dup("+46705182786");
    
    if (strcmp(esc, "D") == 0 || strcmp(esc, "date") == 0)
	return s_dup("2006-11-24 13:37");

    return NULL;
}


int
cmd_help(int argc,
	 char **argv,
	 CONFIG *cfgp) {
  int i, j, nm;
  COMMAND *cp;

  
  if (argc > 1) {
    for (i = 1; i < argc; i++) {
      nm = 0;
      for (j = 0; cmdv[j].name; j++) {
	if (strcmp(cmdv[j].name, argv[i]) == 0) {
	  cp = &cmdv[j];
	  nm = 1;
	  break;
	}
	if (strncmp(cmdv[j].name, argv[i], strlen(argv[i])) == 0) {
	  cp = &cmdv[j];
	  ++nm;
	}
      }

      if (nm < 1) {
	fprintf(stderr, "%s: No such command\n", argv[i]);
	return -1;
      }
      if (nm > 1) {
	fprintf(stderr, "%s: Multiple command matches\n", argv[i]);
	return -1;
      }
      printf("  %-10s\t%-30s\t%s\n", cp->name, cp->args, cp->help);
    }
  } else {
    puts("Commands:");
    for (i = 0; cmdv[i].name; i++) {
      cp = &cmdv[i];
      printf("  %-10s\t%-30s\t%s\n", cp->name, cp->args, cp->help);
    }
    puts("\nAll commands also accept the standard options\n");
    puts("\nOptions:");
    puts("  -h            Display this information");
    puts("  -r            Enable recursive mode");
    puts("  -d            No-depth mode");
    puts("  -n            No-update mode");
    puts("  -v[<level>]   Increase/set verbosity level");
    puts("  -S<style>     ACL print style/format [default, brief, csv, solaris]");
    puts("  -D<level>     Increase debug level");
  }
  
  return 0;
}


int
cfg_parse(CONFIG *cfgp,
	  int *ai,
	  int argc,
	  char **argv) {
  int c, rc;

  rc = 0;
  
  optind = 1;
  optreset = 1;
  while (rc == 0 && (c = getopt_long(argc, argv, SHORT_OPTIONS, long_options, NULL)) != -1) {
    if (c == 'h' || c == '?') {
      char *av[3];

      av[2] = NULL;
      av[1] = argv[optind-2];
      av[0] = "help";
      
      cmd_help(2, av, cfgp);
      return -1;
    } else
      rc = option_set_short(cfgp, c, optarg);
  }
  
  *ai = optind;
  return rc;
}

int
cmd_print(int argc,
	  char **argv,
	  CONFIG *cfgp) {
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
	CONFIG *cfgp) {
  char buf[2048];

  if (getcwd(buf, sizeof(buf)))
    puts(buf);

  return 0;
}

int
cmd_cd(int argc,
       char **argv,
       CONFIG *cfgp) {
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
cmd_config(int argc,
	   char **argv,
	   CONFIG *cfgp) {
  int rc = 0;
  

  if (argc == 1) {
    puts("CONFIGURATION:");
    printf("  Debug Level:        %d\n", cfgp->f_debug);
    printf("  Verbosity Level:    %d\n", cfgp->f_verbose);
    printf("  Recurse:            %s\n", cfgp->f_recurse ? "Yes" : "No");
    printf("  Update:             %s\n", cfgp->f_noupdate ? "No" : "Yes");
    printf("  Style:              %s\n", style2str(cfgp->f_style));
  } else {
    int i;

    
    for (i = 1; i < argc; i++) {
      char *cp = strchr(argv[i], '=');
      if (cp)
	*cp++ = '\0';
      rc = option_set_long(cfgp, argv[i], cp);
      if (rc)
	return rc;
    }
  }

  d_cfg = *cfgp;
  return rc;
}





int
cmd_exit(int argc,
	 char **argv,
	 CONFIG *cfgp) {
  int ec = 0;

  if (argc > 1) {
    if (sscanf(argv[1], "%d", &ec) != 1) {
      fprintf(stderr, "%s: Error: %s: Invalid exit code\n", argv[0], argv[1]);
      return -1;
    }
  }

  exit(ec);
}


COMMAND cmdv[] = {
		  { "help", 	"[<command>]*",			cmd_help, 	"Display this information" },
		  { "exit", 	"[<code>]",			cmd_exit,	"Exit (with exit code)" },
		  { "config", 	"[<opt>[=<val>]]*",		cmd_config,	"Print/update default configuration" },
		  { "print", 	"[<str>]*",			cmd_print,	"Print some text" },
		  { "cd", 	"[<path>]*",			cmd_cd,		"Change working directory" },
		  { "pwd", 	"",				cmd_pwd,	"Print working directory" },
		  
		  { "list",     "<path>+",			cmd_list,	"List ACL(s)" },
		  { "set",      "<path>+",			cmd_set,	"Set ACL(s)" },
		  { "grep",     "<path>+",			cmd_grep,	"Search ACL(s)" },
		  { "edit",     "<path>+",			cmd_edit,	"Edit ACL(s)" },
		  { "strip",    "<path>+",			cmd_strip,	"Strip ACL(s)" },
		  { "sort",     "<path>+",			cmd_sort,	"Sort ACL(s)" },
		  { "inherit",  "<path>+",			cmd_inherit,	"Propage ACL(s) inheritance" },
		  { "check",    "<path>+",			cmd_check,	"Sanity-check ACL(s)" },
		  { "copy",     "<src> <dst>+",			cmd_copy,	"Copy ACL(s)" },
		  
		  { NULL,	NULL,				NULL,		NULL },
};

int
run_cmd(int argc,
	char *argv[],
	CONFIG *cfgp) {
  int ai, i, nm;
  COMMAND *cp;
  CONFIG cfg;
  

  cfg = *cfgp;
  ai = 0;
  if (cfg_parse(&cfg, &ai, argc, argv) != 0)
    return -1;
  
  if (strcmp(argv[0], "?") == 0) {
    if (cfgp != &d_cfg)
      free(argv[0]);
    argv[0] = s_dup("help");
  }
  
  nm = 0;
  for (i = 0; cmdv[i].name; i++) {
    if (strcmp(cmdv[i].name, argv[0]) == 0) {
      cp = &cmdv[i];
      nm = 1;
      break;
    }
    if (strncmp(cmdv[i].name, argv[0], strlen(argv[0])) == 0) {
      cp = &cmdv[i];
      ++nm;
    }
  }

  if (nm == 0) {
    fprintf(stderr, "Error: %s: No such command\n", argv[0]);
    return -1;
  }

  if (nm > 1) {
    fprintf(stderr, "Error: %s: Matches multiple commands\n", argv[0]);
    return -1;
  }

  if (ai > 1) {
    free(argv[ai-1]);
    argv[ai-1] = argv[0];
  }
  
  return (*cp->handler)(argc-ai+1, argv+ai-1, &cfg);
}

  
char *
cmd_name_generator(const char *text,
		   int state) {
  static int ci, len;
  const char *name;
  
  if (!state) {
    ci = 0;
    len = strlen(text);
  }

  while ((name = cmdv[ci++].name) != NULL) {
    if (strncmp(name, text, len) == 0)
      return s_dup(name);
  }

  return NULL;
}

char **
cmd_name_completion(const char *text,
		    int start,
		    int end) {
  rl_attempted_completion_over = 1;
  
  return rl_completion_matches(text, start == 0 ? cmd_name_generator : rl_filename_completion_function);
}



int
main(int argc,
     char **argv)
{
  char *buf;
  char **av;
  int ai, ac, rc;
  

  argv0 = argv[0];

  ai = 0;
  if (cfg_parse(&d_cfg, &ai, argc, argv) != 0)
    exit(1);

  if (ai == argc) {
    if (isatty(fileno(stdin)))
      puts("INTERACTIVE MODE");
    
    rl_attempted_completion_function = cmd_name_completion;
    
    while ((buf = readline("> ")) != NULL) {
      add_history(buf);

      while (*buf && isspace(*buf))
	++buf;
      
      switch (*buf) {
      case '!':
	rc = system(buf+1);
	break;

      case '#':
	break;

      default:
	ac = argv_create(buf, NULL, NULL, &av);
	if (ac > 0)
	  rc = run_cmd(ac, av, &d_cfg);
	
	argv_destroy(av);
      }
      
      free(buf);
      if (rc)
	fprintf(stderr, "ERR");
    }

    exit(rc);
  }
  
  rc = run_cmd(argc-ai, argv+ai, &d_cfg);
  return rc;
}
