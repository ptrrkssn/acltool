/*
 * opts.c - Options parsing
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
#include <ctype.h>
#include <errno.h>

#include "misc.h"
#include "strings.h"
#include "opts.h"


int
opts_print(FILE *fp,
	   OPTION *opts,
	   ...) {
  int i;
  OPTION *optlist;
  va_list ap;

  
  fprintf(fp, "OPTIONS:\n");
  
  va_start(ap, opts);
  optlist = opts;
  while (optlist) {
    for (i = 0; optlist[i].name; i++)
      fprintf(fp, "  -%c / --%-10s\t%s\t%s\n",
	      optlist[i].flag,
	      optlist[i].name,
	      "-",
	      optlist[i].help);
    optlist = va_arg(ap, OPTION *);
  }
  va_end(ap);
  
  return 0;
}


int
opts_set_value(OPTION *op,
	       const char *value,
	       const char *argv0) {
  const char *svp;
  int d;

  
  if (!op) {
    errno = ENOSYS;
    return -1;
  }

  svp = NULL;
  switch (op->type & OPTS_TYPE_MASK) {
  case OPTS_TYPE_NONE:
    if (value) {
      errno = E2BIG; /* Value specified where none should be */
      return -1;
    }
    if (op->dvp && !op->handler)
      ++*(int *)(op->dvp);
    break;

  case OPTS_TYPE_INT:
    if (value) {
      if (sscanf(value, "%d", &d) != 1) {
	errno = EINVAL; /* Invalid integer */
	return -1;
      }
      svp = (const void *) &d;
      if (op->dvp && !op->handler)
	*(int *)(op->dvp) = d;
    } else if (!(op->type & OPTS_TYPE_OPT)) {
      errno = ENOENT; /* Required value missing */
      return -1;
    }
    break;
    
  case OPTS_TYPE_UINT:
    if (value) {
      if (sscanf(value, "%d", &d) != 1 || d < 0) {
	errno = EINVAL;
	return -1;
      }
      svp = (const void *) &d;
      if (op->dvp && !op->handler)
	*(unsigned int *)(op->dvp) = d;
    } else if (!(op->type & OPTS_TYPE_OPT)) {
      errno = ENOENT; /* Required value missing */
      return -1;
    }
    break;
    
  case OPTS_TYPE_STR:
    if (!value && !(op->type & OPTS_TYPE_OPT)) {
      errno = ENOENT;
      return -1;
    }
    svp = (const void *) value;
    if (op->dvp && !op->handler)
      *(char **)(op->dvp) = s_dup(value);
    break;

  default:
    errno = ENOSYS;
    return -1;
  }
  
  if (op->handler)
    return op->handler(op->name, value, op->type, svp, op->dvp, argv0);

  return 0;
}

	       
int
opts_parse_argv(int argc,
		char **argv,
		OPTION *opts,
		...) {
  int i, j, k, nm, rc = 0;
  char *name;
  char *value;
  OPTION *op, *optlist;
  va_list ap;


  for (i = 1; i < argc && argv[i][0] == '-'; i++) {
    if (argv[i][1] == '-') {
      /* Long option (--xploit) */
      if (!argv[i][2]) {
	++i;
	goto EndArg;
      }
      
      name = s_dup(argv[i]+2);
      if (!name)
	return -1;
      
      value = strchr(name, '=');
      if (value)
	*value++ = '\0';
      
      nm = 0;
      op = NULL;
      va_start(ap, opts);
      optlist = opts;
      while (optlist) {
	for (k = 0; optlist[k].name; k++) {
	  if (optlist[k].name && s_match(name, optlist[k].name)) {
	    op = &optlist[k];
	    ++nm;
	  }
	}

	optlist = va_arg(ap, OPTION *);
      }
      va_end(ap);
      free(name);

      if (nm < 1 || !op)
	return error(1, 0, "%s: Invalid option", argv[i]);

      if (nm > 1)
	return error(-1, 0, "%s: Multiple options matches", argv[i]);

      rc = opts_set_value(op, value, argv[0]);
      if (rc != 0)
	return rc;
	
    } else {
      /* Short option (-x) */

      if (!argv[i][1]) {
	++i;
	goto EndArg;
      }
      
      for (j = 1; argv[i][j]; j++) {
	op = NULL;
	nm = 0;
	
	va_start(ap, opts);
	optlist = opts;
	while (optlist) {
	  for (k = 0; optlist[k].name; k++) {
	    if (optlist[k].flag && argv[i][j] == optlist[k].flag) {
	      op = &optlist[k];
	      ++nm;
	    }
	  }

	  optlist = va_arg(ap, OPTION *);
	}
	va_end(ap);
	
	if (nm < 1 || !op)
	  error(1, 0, "-%c: Invalid option", argv[i][j]);
	
	if (nm > 1)
	  error(1, 0, "-%c: Multiple options matches", argv[i][j]);

	value = NULL;
	switch (op->type & OPTS_TYPE_MASK) {
	case OPTS_TYPE_NONE:
	  rc = opts_set_value(op, NULL, argv[0]);
	  break;

	case OPTS_TYPE_INT:
	  value = NULL;
	  if (isdigit(argv[i][j+1]) || (argv[i][j+1] == '-' && isdigit(argv[i][j+2])))
	    value = argv[i]+j+1;
	  else if (argv[i+1] && (isdigit(argv[i+1][0]) || (argv[i+1][0] == '-' && isdigit(argv[i+1][1]))))
	    value = argv[++i];
	  
	  rc = opts_set_value(op, value, argv[0]);
	  break;
	  
	case OPTS_TYPE_UINT:
	  value = NULL;
	  if (isdigit(argv[i][j+1]))
	    value = argv[i]+j+1;
	  else if (argv[i+1] && isdigit(argv[i+1][0]))
	    value = argv[++i];

	  rc = opts_set_value(op, value, argv[0]);
	  break;

	case OPTS_TYPE_STR:
	  if (argv[i][j+1])
	    value = argv[i]+j+1;
	  else if (argv[i+1])
	    value = argv[++i];

	  rc = opts_set_value(op, value, argv[0]);
	  break;
	  
	default:
	  return error(1, 0, "%d: Unknown option type",
		       (op->type & OPTS_TYPE_MASK));
	}

	if (rc != 0)
	  return rc;
	
	if (value)
	  goto NextArg;
      }
    }
  NextArg:;
  }

 EndArg:
  return i;
}




int
opts_set2(OPTION *opts,
	  const char *name,
	  const char *value,
	  const char *argv0) {
  int nm, k;
  OPTION *op;

  
  nm = 0;
  op = NULL;
  for (k = 0; opts[k].name; k++) {
    if (opts[k].name && s_match(name, opts[k].name)) {
      op = &opts[k];
      ++nm;
    }
  }

  if (nm < 1 || !op) {
    errno = ENOENT;
    return -1;
  }
  if (nm > 1) {
    errno = E2BIG;
    return -1;
  }

  return opts_set_value(op, value, argv0);
}


int
opts_set(OPTION *opts,
	 const char *varval,
	 const char *a0) {
  char *name;
  char *value;
  int rc;

  
  name = s_dup(varval);
  value = strchr(name, '=');
  if (value)
    *value++ = '\0';

  rc = opts_set2(opts, name, value, a0);
  free(name);

  return rc;
}



#ifdef TEST
int
test_handler(const char *name,
	     const char *vs,
	     unsigned int type,
	     const void *svp,
	     void *dvp,
	     const char *a0) {
  printf("%s: Setting %s to %s\n", a0, name, vs ? vs : "<NULL>");
  if ((type & OPTS_TYPE_MASK) == OPTS_TYPE_INT)
    printf("int=%d\n", * (const int *) svp);
	    
  return 0;
}

int ival = 0;
unsigned int uval = 0;
char *sval = NULL;

OPTION ov[] =
  {
   { "none",       'n', OPTS_TYPE_NONE, test_handler, NULL,  "No value" },
   { "int-value",  'i', OPTS_TYPE_INT,  NULL,         &ival, "Int value" },
   { "int-rest",   'r', OPTS_TYPE_INT,  test_handler, NULL,  "Int value 2" },
   { "uint-value", 'u', OPTS_TYPE_UINT, test_handler, &uval, "Unsigned Int value" },
   { "str-value",  's', OPTS_TYPE_STR,  test_handler, &sval, "String value" },
   { NULL, 0, 0, NULL, NULL, NULL },
  };
  
int
main(int argc,
     char **argv) {
  int i, rc;

  i = opts_parse_argv(argc, argv, ov, NULL);
  if (i < 0)
    exit(1);

  for (; i < argc; i++) {
    printf("#%d = %s\n", i, argv[i]);
    rc = opts_set(&ov[0], argv[i], argv[0]);
    printf("rc=%d\n", rc);
  }

  printf("ival=%d\n", ival);
  exit(0);
}
#endif

