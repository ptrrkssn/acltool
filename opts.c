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
opts_print(OPTION *opts,
	   FILE *fp) {
  int i;


  fprintf(fp, "OPTIONS:\n");
  for (i = 0; opts[i].name; i++)
    fprintf(fp, "  -%c / --%-10s\t%s\t%s\n",
	    opts[i].flag,
	    opts[i].name,
	    "-",
	    opts[i].help);
  
  return 0;
}

int
opts_parse_argv(OPTION *opts,
		int argc,
		char **argv,
		void *xp) {
  int i, j, k, nm, rc, d;
  char *name;
  char *value;
  void *vp;
  OPTION *op;
  
  
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
      for (k = 0; opts[k].name; k++) {
	if (opts[k].name && s_match(name, opts[k].name)) {
	  op = &opts[k];
	  ++nm;
	}
      }

      free(name);

      if (nm < 1 || !op) {
	fprintf(stderr, "%s: Error: %s: Invalid option\n", argv[0], argv[i]);
	return -1;
      }
      if (nm > 1) {
	fprintf(stderr, "%s: Error: %s: Multiple options matches\n", argv[0], argv[i]);
	return -1;
      }

      vp = NULL;
      switch (op->type & OPTS_TYPE_MASK) {
      case OPTS_TYPE_NONE:
	if (value) {
	  fprintf(stderr, "%s: Error: %s: Value specified\n", argv[0], argv[i]);
	  return -1;
	}
	break;

      case OPTS_TYPE_INT:
	if (value) {
	  if (sscanf(value, "%d", &d) != 1) {
	    fprintf(stderr, "%s: Error: %s: Invalid integer value\n", argv[0], argv[i]);
	    return -1;
	  }
	  vp = (void *) &d;
	} else if (!(op->type & OPTS_TYPE_OPT)) {
	  fprintf(stderr, "%s: Error: %s: Missing required value\n", argv[0], argv[i]);
	  return -1;
	}
	break;
	
      case OPTS_TYPE_UINT:
	if (value) {
	  if (sscanf(value, "%d", &d) != 1 || d < 0) {
	    fprintf(stderr, "%s: Error: %s: Invalid unsigned integer value\n", argv[0], argv[i]);
	    return -1;
	  }
	  vp = (void *) &d;
	} else if (!(op->type & OPTS_TYPE_OPT)) {
	  fprintf(stderr, "%s: Error: %s: Missing required value\n", argv[0], argv[i]);
	  return -1;
	}
	break;

      case OPTS_TYPE_STR:
	if (!value && !(op->type & OPTS_TYPE_OPT)) {
	  fprintf(stderr, "%s: Error: %s: Missing required value\n", argv[0], argv[i]);
	  return -1;
	}
	vp = (void *) value;
	break;
      }
      
      rc = op->handler(op->name, value, op->type, vp, xp, argv[0]);
      if (rc)
	return rc;
    } else {
      /* Short option (-x) */
      
      if (!argv[i][1]) {
	++i;
	goto EndArg;
      }
      
      for (j = 1; argv[i][j]; j++) {
	OPTION *op = NULL;
	
	for (k = 0; opts[k].handler; k++) {
	  if (opts[k].flag && argv[i][j] == opts[k].flag) {
	    op = &opts[k];
	    break;
	  }
	}
	
	if (!op) {
	  fprintf(stderr, "%s: Error: -%c: Invalid option\n", argv[0], argv[i][j]);
	  return -1;
	}

	value = NULL;
	vp = NULL;
	
	switch (op->type & OPTS_TYPE_MASK) {
	case OPTS_TYPE_NONE:
	  break;

	case OPTS_TYPE_INT:
	  if (isdigit(argv[i][j+1]) || (argv[i][j+1] == '-' && isdigit(argv[i][j+2])))
	    value = argv[i]+j+1;
	  else if (argv[i+1] && (isdigit(argv[i+1][0]) || (argv[i+1][0] == '-' && isdigit(argv[i+1][1]))))
	    value = argv[++i];
	  
	  if (value) {
	    if (sscanf(value, "%d", &d) != 1) {
	      fprintf(stderr, "%s: Error: %s: Invalid integer value\n", argv[0], argv[i]);
	      return -1;
	    }
	    vp = (void *) &d;
	  } else if (!(op->type & OPTS_TYPE_OPT)) {
	    fprintf(stderr, "%s: Error: %s: Missing required value\n", argv[0], argv[i]);
	    return -1;
	  }
	  break;
	  
	case OPTS_TYPE_UINT:
	  if (isdigit(argv[i][j+1]))
	    value = argv[i]+j+1;
	  else if (argv[i+1] && isdigit(argv[i+1][0]))
	    value = argv[++i];
	  
	  if (value) {
	    if (sscanf(value, "%d", &d) != 1 || d < 0) {
	      fprintf(stderr, "%s: Error: %s: Invalid unsigned integer value\n", argv[0], argv[i]);
	      return -1;
	    }
	    vp = (void *) &d;
	  } else if (!(op->type & OPTS_TYPE_OPT)) {
	    fprintf(stderr, "%s: Error: %s: Missing required value\n", argv[0], argv[i]);
	    return -1;
	  }
	  break;

	case OPTS_TYPE_STR:
	  if (argv[i][j+1])
	    value = argv[i]+j+1;
	  else if (argv[i+1])
	    value = argv[++i];
	  if (!value && !(op->type & OPTS_TYPE_OPT)) {
	    fprintf(stderr, "%s: Error: %s: Missing required value\n", argv[0], argv[i]);
	    return -1;
	  }
	  vp = (void *) value;
	  break;
	  
	default:
	  fprintf(stderr, "%s: Error: %d: Unknown option type\n",
		  argv[0], (op->type & OPTS_TYPE_MASK));
	  return -1;
	}
	
	rc = op->handler(op->name, value, op->type, vp, xp, argv[0]);
	if (rc)
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
	  void *xp,
	  const char *a0) {
  int nm, k, d;
  OPTION *op;
  void *vp;

  
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
  
  vp = NULL;
  switch (op->type & OPTS_TYPE_MASK) {
  case OPTS_TYPE_NONE:
    if (value) {
      errno = EINVAL;
      return -1;
    }
    break;
    
  case OPTS_TYPE_INT:
    if (value) {
      if (sscanf(value, "%d", &d) != 1) {
	errno = EINVAL;
	return -1;
      }
      vp = (void *) &d;
    }
    break;
    
  case OPTS_TYPE_UINT:
    if (value) {
      if (sscanf(value, "%d", &d) != 1 || d < 0) {
	errno = EINVAL;
	return -1;
      }
      vp = (void *) &d;
    }
    break;
    
  case OPTS_TYPE_STR:
    vp = (void *) value;
  }
  
  return op->handler(op->name, value, op->type, vp, xp, a0);
}


int
opts_set(OPTION *opts,
	 const char *varval,
	 void *xp,
	 const char *a0) {
  char *name;
  char *value;
  int rc;

  
  name = s_dup(varval);
  value = strchr(name, '=');
  if (value)
    *value++ = '\0';

  rc = opts_set2(opts, name, value, xp, a0);
  free(name);

  return rc;
}



#if DEBUG
int
test_handler(const char *name,
	     const char *vs,
	     unsigned int type,
	     void *vp,
	     void *xp,
	     const char *a0) {
  FILE *fp = (FILE *) xp;
  
  fprintf(fp, "%s: Setting %s to %s\n", a0, name, vs ? vs : "<NULL>");
  if ((type & OPTS_TYPE_MASK) == OPTS_TYPE_INT)
    printf("int=%d\n", * (int *) vp);
	    
  return 0;
}

OPTION ov[] =
  {
   { "none",       'n', OPTS_TYPE_NONE, test_handler, "No value" },
   { "int-value",  'i', OPTS_TYPE_INT,  test_handler, "Int value" },
   { "int-rest",   'r', OPTS_TYPE_INT,  test_handler, "Int value 2" },
   { "uint-value", 'u', OPTS_TYPE_UINT, test_handler, "Unsigned Int value" },
   { "str-value",  's', OPTS_TYPE_STR,  test_handler, "String value" },
   { NULL, 0, 0, NULL, NULL },
  };
  
int
main(int argc,
     char **argv) {
  int i, rc;

  i = opts_parse_argv(&ov[0], argc, argv, (void *) stdout);
  if (i < 0)
    exit(1);

  for (; i < argc; i++) {
    printf("#%d = %s\n", i, argv[i]);
    rc = opts_set(&ov[0], argv[i], (void *) stdout);
    printf("rc=%d\n", rc);
  }

  exit(0);
}
#endif

