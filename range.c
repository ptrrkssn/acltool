/*
 * range.c - Integer ranges handling code
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
#include <ctype.h>
#include <errno.h>

#include "range.h"


/* Allocate a new range segment */
static RANGE *
_alloc_range(int p1,
	     int p2) {
  RANGE *rp = malloc(sizeof(*rp));

  if (!rp)
    return NULL;

#if RANGE_DEBUG
  rp->magic = RANGE_MAGIC;
#endif
  
  if (p1 <= p2) {
    rp->min = p1;
    rp->max = p2;
  } else {
    rp->min = p2;
    rp->max = p1;
  }

  rp->next = NULL;
  return rp;
}


/* Check in a value is inside a range segment */
static int
_in_range(RANGE *rp,
	  int p) {
  if (!rp) {
    errno = EINVAL;
    return 0;
  }
  
  return (p >= rp->min && p <= rp->max);
}



/* Free and destroy all segments in a range */
void
range_free(RANGE **rpp) {
  RANGE *rp, *nrp;

  
  if (!rpp || !*rpp) {
    errno = EINVAL;
    return;
  }

  for (rp = *rpp; rp; rp = nrp) {
#if RANGE_DEBUG
    if (rp->magic != RANGE_MAGIC) {
      if (rp->magic == RANGE_MAGIC_FREED)
	fprintf(stderr, "*** range_free(%p): Double free\n", rp);
      else
	fprintf(stderr, "*** range_free(%p): Invalid magic=0x%08x\n", rp, rp->magic);
      abort();
    }
    rp->magic = RANGE_MAGIC_FREED;
#endif
    
    nrp = rp->next;
    free(rp);
  }
  *rpp = NULL;
}


/* Return the number of integers in a range */
int
range_len(RANGE *rp) {
  int n, d;

  
  if (!rp) {
    errno = EINVAL;
    return -1;
  }

#if RANGE_DEBUG
  if (rp->magic != RANGE_MAGIC) {
    fprintf(stderr, "*** range_len(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
    abort();
  }
#endif
  
  n = 0;
  while (rp) {
    if (rp->max == RANGE_END && rp->min == RANGE_END)
      d = 1;
    else if (rp->max == RANGE_END)
      return RANGE_END;
    else
      d = rp->max-rp->min+1;
    
    n += d;
    rp = rp->next;
  }
  
  return n;
}


/* Return the lowest integer in a range */
int
range_first(RANGE *rp,
	    int *p) {
  if (!rp) {
    errno = EINVAL;
    return -1;
  }

#if RANGE_DEBUG
  if (rp->magic != RANGE_MAGIC) {
    fprintf(stderr, "*** range_first(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
    abort();
  }
#endif
  
  *p = rp->min;
  return 0;
}


/* Return the highest integer in a range */
int
range_last(RANGE *rp,
	   int *p) {
  if (!rp) {
    errno = EINVAL;
    return -1;
  }

#if RANGE_DEBUG
  if (rp->magic != RANGE_MAGIC) {
    fprintf(stderr, "*** range_last(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
    abort();
  }
#endif
  
  while (rp->next)
    rp = rp->next;
  
  *p = rp->max;
  return 0;
}


int
range_next(RANGE *rp,
	   int *pp) {
  RANGE *trp = rp;

  
  if (!rp || !pp) { 
    errno = EINVAL;
    return -1;
  }
  
#if RANGE_DEBUG
  if (rp->magic != RANGE_MAGIC) {
    fprintf(stderr, "*** range_next(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
    abort();
  }
#endif
  
  while (rp) {
    if (_in_range(rp, *pp)) {
      if (*pp+1 <= rp->max) {
	*pp = *pp+1;
	return 1;
      } else if (rp->next) {
	*pp = rp->next->min;
	return 1;
      } else
	return 0;
    }
    rp = rp->next;
  }

  *pp = trp->min;
  return 1;
}

int
range_prev(RANGE *rp,
	   int *pp) {
  RANGE *prp;

  
  if (!rp || !pp) {
    errno = EINVAL;
    return -1;
  }

#if RANGE_DEBUG
  if (rp->magic != RANGE_MAGIC) {
    fprintf(stderr, "*** range_prev(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
    abort();
  }
#endif
  
  prp = NULL;
  while (rp) {
    if (_in_range(rp, *pp)) {
      if (*pp-1 >= rp->min) {
	*pp = *pp-1;
	return 1;
      } else if (prp) {
	*pp = prp->max;
	return 1;
      } else
	return 0;
    }
    prp = rp;
    rp = rp->next;
  }

  *pp = prp->max;
  return 1;
}


/* Add a segment to a range */
int
range_add(RANGE **rpp,
	  int p1,
	  int p2) {
  RANGE *rp;


  if (!rpp) {
    errno = ENOMEM;
    return -1;
  }

  if (p2 < p1) {
    int t = p2;
    
    p2 = p1;
    p1 = t;
  }
  

  /* Locate where to insert/append */
  for (rp = *rpp; rp; rp = rp->next) {
#if RANGE_DEBUG
    if (rp->magic != RANGE_MAGIC) {
      fprintf(stderr, "*** range_add(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
      abort();
    }
#endif
    
    /* Completely contained within a previous segment */
    if (_in_range(rp, p1) && _in_range(rp, p2))
      return 0;

    /* Append to a partly overlapping segment */
    if (_in_range(rp, p1) || rp->max+1 == p1) {
      RANGE *nrp;

      rp->max = p2;
      
      /* Merge overlapping segments */
      while ((nrp = rp->next) && (rp->max+1 == nrp->min || _in_range(rp, nrp->max))) {
	if (rp->max+1 == nrp->min)
	  rp->max = nrp->max;
	rp->next = nrp->next;
	free(nrp);
      }
      return 0;
    }

    /* Prepend to a partly overlapping segment */
    if (_in_range(rp, p2) || p2+1 == rp->min) {
      rp->min = p1;
      return 0;
    }

    /* Found the position where to insert new segment */
    if (p2 < (rp->min > 0 ? rp->min-1 : rp->min))
      break;
    
    rpp = &rp->next;
  }

  /* Allocate new segment */
  rp = _alloc_range(p1,p2);
  if (!rp)
    return -1;

  /* Insert into range */
  rp->next = *rpp;
  *rpp = rp;

  return 0;
}


int
range_addn(RANGE **rpp,
	   int p,
	   int n) {
  return range_add(rpp, p, (n == RANGE_END ? RANGE_END : p + n));
}


int
range_adds(RANGE **rpp,
	   const char **spp) {
  const char *sp;
  char *ep;
  int n = 0;
  

  if (!rpp) {
    errno = ENOMEM;
    return -1;
  }
  
  if (!spp || !*spp) {
    errno = EINVAL;
    return -1;
  }
  
  sp = *spp;
  
  while (*sp && (isdigit(*sp) || *sp == '$')) {
    int p1, p2;

    /* Get start */
    if (*sp == '$') {
      p1 = RANGE_END;
      ++sp;
    } else {
      errno = 0;
      p1 = strtoul(sp, &ep, 0);
      if ((p1 == 0 && (errno == EINVAL || errno == ERANGE)) || (sp == ep))
	return -1;
      sp = ep;
    }
    p2 = p1;
    
    if (*sp == '-') {
      /* Get range */
      ++sp;
      if (*sp == '+') {
	/* Get length */
	errno = 0;
	n = strtoul(sp, &ep, 10);
	if ((n == 0 && (errno == EINVAL || errno == ERANGE)) || (sp == ep))
	  return -1;
	p2 = p1+n;
	sp = ep;
      } else {
	/* Get last */
	if (*sp == '$') {
	  p2 = RANGE_END;
	  ++sp;
	} else {
	  errno = 0;
	  p2 = strtol(sp, &ep, 10);
	  if ((p2 == 0 && (errno == EINVAL || errno == ERANGE)) || (sp == ep))
	    return -1;
	  sp = ep;
	}
      }
    }

    if (range_add(rpp, p1, p2) < 0) {
      errno = EINVAL;
      return -1;
    }
    ++n;
    
    while (isspace(*sp))
      ++sp;
    
    if (*sp != ',')
      break;
    ++sp;
  }

  *spp = sp;
  return n;
}





static int
_print_value(int v,
	     FILE *fp) {
  if (v == RANGE_END)
    return putc('$', fp);

  return fprintf(fp, "%u", v);
}

int
range_print(RANGE *rp, FILE *fp) {
#if RANGE_DEBUG
  if (rp->magic != RANGE_MAGIC) {
    fprintf(stderr, "*** range_printf(%p): Invalid magic (0x%08x)\n", rp, rp->magic);
    abort();
  }
#endif
  
  while (rp) {
    if (_print_value(rp->min, fp) < 0)
      return -1;
    if (rp->min != rp->max) {
      if (putc('-', fp) < 0)
	return -1;
      if (_print_value(rp->max, fp) < 0)
	return -1;
    }
    if (rp->next)
      if (putc(',', fp) < 0)
	return -1;
    rp = rp->next;
  }
  return 0;
}


#ifdef TEST
int
main(int argc,
     char **argv) {
  RANGE *rp = NULL;
  int i, len, min, max, p;
  
  
  for (i = 1; i < argc; i++) {
    int rc;
    const char *sp = argv[i];

    
    rc = range_adds(&rp, &sp);
    if (rc < 0) {
      fprintf(stderr, "%s: Error: %s: Invalid range\n", argv[0], argv[i]);
      exit(1);
    }
  }

  range_first(rp, &min);
  range_last(rp, &max);
  len = range_len(rp);
  
  printf("Range (len=%d, min=%d, max=%d):\n", len, min, max);
  range_print(rp, stdout);
  putchar('\n');

  if (len < 100) {
    puts("Forward:");
    p = RANGE_NONE;
    while (range_next(rp, &p) == 1)
      if (p == RANGE_END)
	printf("$ ");
      else
	printf("%d ", p);
    puts("");
    
    puts("Backwards:");
    p = RANGE_NONE;
    while (range_prev(rp, &p) == 1)
      if (p == RANGE_END)
	printf("$ ");
      else
	printf("%d ", p);
    puts("");
  }
  
  return 0;
}
#endif
