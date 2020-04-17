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
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <ftw.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "acltool.h"



char *version = "1.6.1";

COMMANDS commands;

char *argv0 = "acltool";

CONFIG d_cfg = { 0, 0, 0, 0, 0, 0 };



int
set_debug(const char *name,
	  const char *value,
	  unsigned int type,
	  void *vp,
	  void *xp,
	  const char *a0) {
  CONFIG *cp = (CONFIG *) xp;

  if (vp)
    cp->f_debug = * (int *) vp;
  else
    cp->f_debug++;

  return 0;
}

int
set_verbose(const char *name,
	    const char *value,
	    unsigned int type,
	    void *vp,
	    void *xp,
	    const char *a0) {
  CONFIG *cp = (CONFIG *) xp;
  
  if (vp)
    cp->f_verbose = * (int *) vp;
  else
    cp->f_verbose++;
  
  return 0;
}

int
set_sort(const char *name,
	 const char *value,
	 unsigned int type,
	 void *vp,
	 void *xp,
	 const char *a0) {
  CONFIG *cp = (CONFIG *) xp;
  
  cp->f_sort++;
  
  return 0;
}

int
set_merge(const char *name,
	  const char *value,
	  unsigned int type,
	  void *vp,
	  void *xp,
	  const char *a0) {
  CONFIG *cp = (CONFIG *) xp;
  
  cp->f_merge++;
  
  return 0;
}

int
set_recurse(const char *name,
	    const char *value,
	    unsigned int type,
	    void *vp,
	    void *xp,
	    const char *a0) {
  CONFIG *cp = (CONFIG *) xp;

  
  if (vp) {
    int v = * (int *) vp;
    
    if (v < -1)
      v = -1;
    
    cp->max_depth = v;
  }
  else
    cp->max_depth = -1;
  
  return 0;
}

int
set_depth(const char *name,
	  const char *value,
	  unsigned int type,
	  void *vp,
	  void *xp,
	  const char *a0) {
  CONFIG *cp = (CONFIG *) xp;
  
  if (vp) {
    int v = * (int *) vp;
    
    cp->max_depth += v;
  }
  else
    cp->max_depth++;
  
  return 0;
}

int
set_style(const char *name,
	  const char *value,
	  unsigned int type,
	  void *vp,
	  void *xp,
	  const char *a0) {
  CONFIG *cp = (CONFIG *) xp;

  
  if (value) {
    if (str2style(value, &cp->f_style) != 1)
      return -1;
  } else
    cp->f_style++;
  
  return 0;
}

int
set_no_update(const char *name,
	      const char *value,
	      unsigned int type,
	      void *vp,
	      void *xp,
	      const char *a0) {
  CONFIG *cp = (CONFIG *) xp;

  cp->f_noupdate = 1;
  return 0;
}

extern OPTION options[];

int
show_help(const char *name,
	  const char *value,
	  unsigned int type,
	  void *vp,
	  void *xp,
	  const char *a0) {
  printf("USAGE:\n  %s [<options>] [<command>]\n\n", a0);
  
  opts_print(&options[0], stdout);

  puts("\nUse 'help' to get more information about the available commands");
  return -1;
}



OPTION options[] =
  {
   { "help",      'h', OPTS_TYPE_NONE,               show_help,     "Display usage" },
   { "debug",     'D', OPTS_TYPE_UINT|OPTS_TYPE_OPT, set_debug,     "Debug level" },
   { "verbose",   'v', OPTS_TYPE_UINT|OPTS_TYPE_OPT, set_verbose,   "Verbosity level" },
   { "sort",      's', OPTS_TYPE_NONE,               set_sort,      "Enable sorting" },
   { "merge",     'm', OPTS_TYPE_NONE,               set_merge,     "Enable merging" },
   { "recurse",   'r', OPTS_TYPE_INT|OPTS_TYPE_OPT,  set_recurse,   "Enable recursion" },
   { "depth",     'd', OPTS_TYPE_INT|OPTS_TYPE_OPT,  set_depth,     "Increase/decrease max depth" },
   { "style",     'S', OPTS_TYPE_STR,                set_style,     "Select ACL print style" },
   { "no-update", 'n', OPTS_TYPE_NONE,               set_no_update, "Disable modification" },
   { NULL,        -1,  0,                            NULL,          NULL },
  };



int
cfg_parse(CONFIG *cfgp,
	  int *ai,
	  int argc,
	  char **argv) {
  int rc;

  
  rc = opts_parse_argv(&options[0], argc, argv, cfgp);
  if (rc < 0)
    return rc;
  
  *ai = rc;
  return 0;
}


void
print_version(void) {
  printf("[ACLTOOL, v%s - Copyright (c) 2020 Peter Eriksson <pen@lysator.liu.se>]\n", version);
}

int
cmd_version(int argc,
	    char **argv,
	    void *vp) {
  print_version();
  puts("");
  puts("Author: Peter Eriksson <pen@lysator.liu.se>");
  puts("Built:  " __DATE__ " " __TIME__);
  puts("Source: https://github.com/ptrrkssn/acltool");
  return 0;
}

int
cmd_config(int argc,
	   char **argv,
	   void *vp) {
  int rc = 0;
  CONFIG *cfgp = (CONFIG *) vp;

  
  if (argc == 1) {
    puts("CONFIGURATION:");
    printf("  Debug Level:        %d\n", cfgp->f_debug);
    printf("  Verbosity Level:    %d\n", cfgp->f_verbose);
    if (cfgp->max_depth < 0)
      printf("  Recurse Max Depth:  No Limit\n");
    else
      printf("  Recurse Max Depth:  %d\n", cfgp->max_depth);
    printf("  Update:             %s\n", cfgp->f_noupdate ? "No" : "Yes");
    printf("  Style:              %s\n", style2str(cfgp->f_style));
  } else {
    int i;

    
    for (i = 1; i < argc; i++) {
      rc = opts_set(options, argv[i], vp, argv[0]);
      if (rc)
	return rc;
    }
  }

  d_cfg = *cfgp;
  return rc;
}


int
cmd_help(int argc,
	 char **argv,
	 void *vp) {
  int i, rc = 0;

  
  if (argc == 1) {
    rc =_cmd_help(&commands, NULL);

    putchar('\n');
    opts_print(&options[0], stdout);
    
    puts("\nDETAILS:");
    puts("  All options & commands may be abbreviated as long as they are unique.");
    puts("  For option & command names consisting of multiple 'parts' (list-access)");
    puts("  the name may be abbreviated using characters from each part, for example:");
    puts("    -n / -no / --nu     = --no-update");
    puts("    lac / list / list-a = list-access");
    puts("    edac / edit / ed-ac = edit-access");
    putchar('\n');
    puts("  If invoked without a command the tool will enter an interactive mode.");
    puts("  All commands take the same options and they can also be used in the interactive mode.");
    putchar('\n');
    puts("  ACL styles supported: default, csv, brief, verbose, samba, icacls, solaris, primos");
    putchar('\n');
    puts("  You may access environment variables using ${NAME}.");
  } else {
    for (i = 1; i < argc; i++) {
      rc = _cmd_help(&commands, argv[i]);
      if (rc < 0)
	break;
    }
  }

  return rc;
}


COMMAND acltool_commands[] = {
  { "version",  "",                	cmd_version,    "Display program version" },
  { "config", 	"[<opt>[=<val>]]*",	cmd_config,	"Print/update default configuration" },
  { "help",     "[<command>]*",         cmd_help,       "Display usage information" },
  { NULL,	NULL,			NULL,		NULL },
};


  
char *
cmd_name_generator(const char *text,
		   int state) {
  static int ci;
  COMMAND *cp;
  
  
  if (!state)
    ci = 0;

  while (ci < commands.cc) {
    cp = commands.cv[ci];
    ++ci;
    
    if (s_match(text, cp->name))
      return s_dup(cp->name);
  }
  
  return NULL;
}

char *
opt_name_generator(const char *text,
			int state) {
  static int ci;
  const char *cp;
  int t;
  
  
  if (!state)
    ci = 0;

  while (options[ci].name) {
    cp = options[ci].name;
    t = options[ci].type;
    ++ci;
    
    if (s_match(text+2, cp))
      return s_cat("--", cp,
		   (((t & OPTS_TYPE_MASK) != OPTS_TYPE_NONE &&
		     !(t & OPTS_TYPE_OPT)) ? "=" : NULL),
		   NULL);
  }
  
  return NULL;
}

char **
cmd_name_completion(const char *text,
		    int start,
		    int end) {
  int i;
  char *(*cng)(const char *text, int state);
  
  rl_attempted_completion_over = 1;

  cng = cmd_name_generator;

  for (i = 0; isspace(rl_line_buffer[i]); i++)
    ;

  if (start > i) {
    if (text[0] == '-' && text[1] == '-')
      cng = opt_name_generator;
    else
      cng = rl_filename_completion_function;
  }
  
  return rl_completion_matches(text, cng);
}



int
run_cmd(int argc,
	char **argv,
	CONFIG *cp,
	void (*freef)(void *p)) {
  CONFIG cfg;
  int ai, rc, i;
  
  
  cfg = *cp;
  
  ai = 0;
  if (cfg_parse(&cfg, &ai, argc, argv) != 0)
    return -1;

  while (--ai) {
    if (freef)
      freef(argv[1]);
    for (i = 1; i < argc-1; i++) {
      argv[i] = argv[i+1];
    }
    --argc;
  }
  argv[argc] = NULL;
  
  rc = cmd_run(&commands, argc, argv, (void *) &cfg);
  if (rc < 0) {
    fprintf(stderr, "%s: Error: %s\n", argv[0], strerror(errno));
    return 1;
  }
  
  return rc;
}


int
main(int argc,
     char **argv)
{
  char *buf;
  char **av;
  int ai, ac, rc = 0;
  char *aname;
  

  aname = strrchr(argv[0], '/');
  if (aname)
    ++aname;
  else
    aname = argv[0];

  argv0 = argv[0];

  cmd_init(&commands);
  cmd_register(&commands, 0, basic_commands);
  cmd_register(&commands, 0, acltool_commands);
  cmd_register(&commands, 0, acl_commands);

  if (strcmp(aname, "acltool") != 0) {
    argv[0] = s_dup(aname);
    rc = run_cmd(argc, argv, &d_cfg, NULL);
    return rc;
  }
  
  ai = 0;
  if (cfg_parse(&d_cfg, &ai, argc, argv) != 0)
    exit(1);

  if (ai == argc) {
    char *stdin_path = NULL;
    char *stdout_path = NULL;
    
    if (isatty(fileno(stdin))) {
      print_version();
      puts("\nINTERACTIVE MODE (type 'help' for information)");
    }
    
    rl_attempted_completion_function = cmd_name_completion;
    
    while ((buf = readline(rc > 0 ? "! " : (rc < 0 ? "? " : "> "))) != NULL) {
      char *cp;

      
      add_history(buf);

      while (*buf && isspace(*buf))
	++buf;

      stdout_path = strrchr(buf, '>');
      stdin_path  = strrchr(buf, '<');
      
      if (stdout_path) {
	*stdout_path++ = '\0';
	for (cp = stdout_path; *cp && !isspace(*cp); ++cp)
	  ;
	*cp = '\0';
      }
      
      if (stdin_path) {
	*stdin_path++ = '\0';
	for (cp = stdin_path; *cp && !isspace(*cp); ++cp)
	  ;
	*cp = '\0';
      }
      
      if (stdout_path) {
	fprintf(stderr, "stdout_path='%s'\n", stdout_path);
	if (freopen(stdout_path, "w", stdout) == NULL)
	  freopen("/dev/tty", "w", stdout);
      }

      if (stdin_path) {
	fprintf(stderr, "stdin_path='%s'\n", stdin_path);
	if (freopen(stdin_path, "w", stdin) == NULL)
	  freopen("/dev/tty", "r", stdin);
      }
      
      switch (*buf) {
      case '!':
	rc = system(buf+1);
	break;

      case '#':
	break;

      default:
	ac = argv_create(buf, NULL, NULL, &av);
	if (ac > 0) {
	  rc = run_cmd(ac, av, &d_cfg, free);
	}
	
	argv_destroy(av);
      }
      
      free(buf);

      if (stdout_path)
	freopen("/dev/tty", "w", stdout);

      if (stdin_path)
	freopen("/dev/tty", "r", stdin);
    }

    exit(rc);
  }

  rc = run_cmd(argc-ai, argv+ai, &d_cfg, NULL);
  return rc;
}
