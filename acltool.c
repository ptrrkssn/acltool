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
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <ftw.h>
#include <setjmp.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "acltool.h"


#if ENABLE_SMB
#include "smb.h"
#endif

char *argv0 = "acltool";
char *version = "1.12.4";

COMMANDS commands = { 0 };

CONFIG default_config = { 0, 0, 0, 0, 0, 0 };
CONFIG config = { 0, 0, 0, 0, 0, 0 };

int f_interactive = 0;



int
set_debug(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  if (svp)
    config.f_debug = * (int *) svp;
  else
    config.f_debug++;

  return 0;
}

int
set_verbose(const char *name,
	    const char *value,
	    unsigned int type,
	    const void *svp,
	    void *dvp,
	    const char *a0) {
  if (svp)
    config.f_verbose = * (int *) svp;
  else
    config.f_verbose++;
  
  return 0;
}

int
set_force(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  if (svp)
    config.f_force = * (int *) svp;
  else
    config.f_force++;
  return 0;
}

int
set_print(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  if (svp)
    config.f_print = * (int *) svp;
  else
    config.f_print++;
  
  return 0;
}

int
set_relaxed(const char *name,
	    const char *value,
	    unsigned int type,
	    const void *svp,
	    void *dvp,
	    const char *a0) {
  if (svp)
    config.f_relaxed = * (int *) svp;
  else
    config.f_relaxed++;
  
  return 0;
}

int
set_sort(const char *name,
	 const char *value,
	 unsigned int type,
	 const void *svp,
	 void *dvp,
	 const char *a0) {
  config.f_sort++;
  
  return 0;
}

int
set_merge(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  config.f_merge++;
  
  return 0;
}

#if ENABLE_SMB
int
set_password(const char *name,
	     const char *value,
	     unsigned int type,
	     const void *svp,
	     void *dvp,
	     const char *a0) {
  smb_init(SMB_PROMPT_PASSWORD);
  return 0;
}
#endif


int
set_recurse(const char *name,
	    const char *value,
	    unsigned int type,
	    const void *svp,
	    void *dvp,
	    const char *a0) {
  if (svp) {
    int v = * (int *) svp;
    
    if (v < -1)
      v = -1;
    
    config.max_depth = v;
  }
  else
    config.max_depth = -1;
  
  return 0;
}

int
set_depth(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  if (svp) {
    int v = * (int *) svp;
    
    config.max_depth += v;
  }
  else
    config.max_depth++;
  
  return 0;
}

int
set_style(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  if (value) {
    if (str2style(value, &config.f_style) != 1)
      return -1;
  } else
    config.f_style++;
  
  return 0;
}

int
set_filetype(const char *name,
	     const char *value,
	     unsigned int type,
	     const void *svp,
	     void *dvp,
	     const char *a0) {
  if (value) {
    if (str2filetype(value, &config.f_filetype) != 1)
      return -1;
  } else
    return -1;
  
  return 0;
}

int
set_no_update(const char *name,
              const char *value,
              unsigned int type,
              const void *svp,
              void *dvp,
              const char *a0) {
  config.f_noupdate = 1;
  return 0;
}

int
set_no_prefix(const char *name,
              const char *value,
              unsigned int type,
              const void *svp,
              void *dvp,
              const char *a0) {
  config.f_noprefix = 1;
  return 0;
}

extern OPTION global_options[];


int
show_help(const char *name,
	  const char *value,
	  unsigned int type,
	  const void *svp,
	  void *dvp,
	  const char *a0) {
  cmd_help(&commands, a0, stdout, 1);
  return -1;
}



OPTION global_options[] =
  {
   { "help",      	'h', OPTS_TYPE_NONE,               show_help,     NULL, "Display usage" },
   { "debug",     	'D', OPTS_TYPE_UINT|OPTS_TYPE_OPT, set_debug,     NULL, "Debug level" },
   { "verbose",   	'v', OPTS_TYPE_NONE,               set_verbose,   NULL, "Verbosity level" },
   { "force",     	'f', OPTS_TYPE_NONE,               set_force,     NULL, "Force updates" },
   { "print",     	'p', OPTS_TYPE_UINT|OPTS_TYPE_OPT, set_print,     NULL, "Print updated ACLs" },
   { "sort",      	's', OPTS_TYPE_NONE,               set_sort,      NULL, "Sort ACLs" },
   { "merge",     	'm', OPTS_TYPE_NONE,               set_merge,     NULL, "Merge redunant ACL entries" },
   { "relaxed",      	'R', OPTS_TYPE_NONE,               set_relaxed,   NULL, "Relaxed mode" },
   { "recurse",   	'r', OPTS_TYPE_INT|OPTS_TYPE_OPT,  set_recurse,   NULL, "Enable recursion" },
   { "depth",     	'd', OPTS_TYPE_INT|OPTS_TYPE_OPT,  set_depth,     NULL, "Increase/decrease max depth" },
   { "style",     	'S', OPTS_TYPE_STR,                set_style,     NULL, "Select ACL print style" },
   { "type",      	't', OPTS_TYPE_STR,                set_filetype,  NULL, "File types to operate on" },
#if ENABLE_SMB
   { "password",      	'P', OPTS_TYPE_NONE,               set_password,  NULL, "Prompt for user password (SMB)" },
#endif
   { "no-update", 	'n', OPTS_TYPE_NONE,               set_no_update, NULL, "Disable modification" },
   { "no-prefix", 	'N', OPTS_TYPE_NONE,               set_no_prefix, NULL, "Do not prefix filenames" }, 
   { NULL,        	-1,  0,                            NULL,          NULL, NULL },
  };



int
cfg_parse(CONFIG *cfgp,
	  int *ai,
	  int argc,
	  char **argv) {
  int rc;

  
  rc = opts_parse_argv(argc, argv, &global_options[0], NULL);
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
version_cmd(int argc,
	    char **argv) {
  print_version();
  puts("");
  puts("Author:  Peter Eriksson <pen@lysator.liu.se>");
  puts("Built:   " __DATE__ " " __TIME__);
  puts("Source:  https://github.com/ptrrkssn/acltool");
#ifdef ENABLE_SMB
  puts("Options: SMB");
#endif  
  return 0;
}


int
config_cmd(int argc,
	   char **argv) {
  int rc = 0;

  
  if (argc == 1) {
    puts("CONFIGURATION:");
    printf("  Debug Level:        %d\n", config.f_debug);
    printf("  Verbosity Level:    %d\n", config.f_verbose);
    printf("  Force Mode:         %s\n", config.f_force ? "Yes" : "No");
    printf("  Sort Mode:          %s\n", config.f_sort ? "Yes" : "No");
    printf("  Merge Mode:         %s\n", config.f_merge ? "Yes" : "No");
    printf("  Relaxed Mode:       %s\n", config.f_relaxed ? "Yes" : "No");
    printf("  Recurse Mode:       %s\n", config.f_recurse ? "Yes" : "No");
    if (config.max_depth < 0)
      printf("  Recurse Max Depth:  No Limit\n");
    else
      printf("  Recurse Max Depth:  %d\n", config.max_depth);
    printf("  Print Level:        %d\n", config.f_print);
    printf("  Update:             %s\n", config.f_noupdate ? "No" : "Yes");
    printf("  Prefix:             %s\n", config.f_noprefix ? "No" : "Yes");
    printf("  Style:              %s\n", style2str(config.f_style));
  } else {
    int i;

    
    for (i = 1; i < argc; i++) {
      rc = opts_set(global_options, argv[i], argv[0]);
      if (rc)
	return rc;
    }
  }

  default_config = config;
  return rc;
}


int
help_cmd(int argc,
	 char **argv) {
  int i, rc = 0;


  if (argc == 1) {
    rc = cmd_help(&commands, NULL, stdout, 0);

    putchar('\n');
    opts_print(stdout, &global_options[0], NULL);
    
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
      rc = cmd_help(&commands, argv[i], stdout, 1);
      if (rc < 0)
	break;
    }
  }

  return rc;
}


COMMAND version_command = 
  { "version",  version_cmd,	NULL, "",                	"Display program version" };

COMMAND config_command =
  { "config", 	config_cmd,	NULL, "[<opt>[=<val>]]*",	"Print/update default configuration" };

COMMAND help_command = 
  { "help",     help_cmd,	NULL, "[<command>]*",      	"Display usage information" };
  
COMMAND *acltool_commands[] =
  {
   &version_command,
   &config_command,
   &help_command,
   NULL,
  };


  
char *
cmd_name_generator(const char *text,
		   int state) {
  static int ci;
  COMMAND *cp;
  
  
  if (!state)
    ci = 0;

  while (ci < commands.c) {
    cp = commands.v[ci];
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

  /* XXX TODO: Handle command options too - not just global ones */
  while (global_options[ci].name) {
    cp = global_options[ci].name;
    t = global_options[ci].type;
    ++ci;
    
    if (s_match(text+2, cp))
      return s_dupcat("--", cp,
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
	char **argv) {
  int rc;
  

  config = default_config;
  rc = cmd_run(&commands, argc, argv);
  if (rc > 0)
    error(rc, errno, "%s", argv[0]);
  return rc;
}


int
main(int argc,
     char **argv)
{
  char *buf;
  char **av;
  int ac, rc = 0;
  char *aname;
  int i, j;
  jmp_buf saved_error_env;
  

  aname = strrchr(argv[0], '/');
  if (aname)
    ++aname;
  else
    aname = argv[0];

  argv0 = s_dup(argv[0]);
  error_argv0 = s_dup(error_argv0);

  cmd_register(&commands, basic_commands);
  cmd_register(&commands, acltool_commands);
  cmd_register(&commands, acl_commands);

  if (strcmp(aname, "acltool") != 0) {
    /* Shortcut to acl-cmd */
    argv[0] = s_dup(aname);
    
    rc = error_catch(saved_error_env);
    if (rc)
      exit(rc);
    
    rc = run_cmd(argc, argv);
    return rc;
  }

  i = opts_parse_argv(argc, argv, global_options, NULL);
  if (i < 0)
    return 1;
  
  default_config = config;
  for (j = 1; i < argc; i++, j++)
    argv[j] = argv[i];
  argv[j] = NULL;
  argc = j;
  
  if (argc == 1) {
    char *stdin_path = NULL;
    char *stdout_path = NULL;

    
    if (isatty(fileno(stdin))) {
      print_version();
      puts("\nINTERACTIVE MODE (type 'help' for information)");
      f_interactive = 1;
    }

    rl_attempted_completion_function = cmd_name_completion;
    
    rc = error_catch(saved_error_env);
    
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
	if (freopen(stdout_path, "w", stdout) == NULL)
	  if (freopen("/dev/tty", "w", stdout) == NULL)
	    exit(1);
      }

      if (stdin_path) {
	if (freopen(stdin_path, "w", stdin) == NULL)
	  if (freopen("/dev/tty", "r", stdin) == NULL)
	    exit(1);
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
	  rc = run_cmd(ac, av);
	}
	argv_destroy(av);
      }
      
      free(buf);

      if (stdout_path)
	if (freopen("/dev/tty", "w", stdout) == NULL)
	  exit(1);

      if (stdin_path)
	if (freopen("/dev/tty", "r", stdin) == NULL)
	  exit(1);
    }

    exit(rc);
  }

  rc = error_catch(saved_error_env);
  if (rc)
    exit(rc);
  
  return run_cmd(argc-1, argv+1);
}
