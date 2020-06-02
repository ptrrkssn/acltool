/*
 * string.c - String manipulation functions
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "strings.h"

#define NEW(vp) ((vp) = malloc(sizeof(*(vp))))


char *
s_dup(const char *s)
{
  if (!s)
    return NULL;
  
  return strdup(s);
}

char *
s_ndup(const char *s,
       size_t len)
{
  if (!s)
    return NULL;
  
  return strndup(s, len);
}


int
s_trim(char *s) {
  char *cp, *dp;

  for (cp = s; *cp && isspace(*cp); ++cp)
    ;
  dp = s;
  if (cp > s) {
    while (*cp)
      *dp++ = *cp++;
  } else
    while (*dp)
      ++dp;

  while (dp > s && isspace(dp[-1]))
    --dp;
  *dp = '\0';
  return dp-s;
}


/*
 * "lac" vs "list-access" = OK
 * "list" vs "list-access" = OK
 */
int
s_match(const char *a,
	const char *b) {
  int ai, bi, mlen;
  

  ai = bi = 0;
  while (a[ai]) {
    /* For each segment */
    mlen = 0;
    
    while (a[ai] && a[ai] == b[bi]) {
      ++ai;
      ++bi;
      ++mlen;
    }
    
    /* At end of 'a' - signal MATCH */
    if (!a[ai])
      return 1;

    /* Segment doesn't match at all -> signal FAIL */
    if (mlen == 0)
      return 0;

    if (a[ai] == '-' || b[bi] != '-') {
      if (a[ai] == '-')
	++ai;
      
      while (b[bi] && b[bi] != '-')
	++bi;
      
      if (!b[bi])
	return a[ai]-b[bi] ? 0 : 1;
    }
    
    ++bi;
  }
  
  return 0;
}


char *
s_dupcat(const char *str,
	 ...) {
  va_list ap;
  char *buf, *cp;
  size_t len;
  
  
  if (!str)
    return NULL;
  
  va_start(ap, str);
  len = strlen(str)+1;
  while ((cp = va_arg(ap, char *)) != NULL)
    len += strlen(cp);
  va_end(ap);
  
  buf = malloc(len);
  if (!buf)
    return NULL;
  
  va_start(ap, str);
  s_cpy(buf, len, str);
  while ((cp = va_arg(ap, char *)) != NULL)
    s_cat(buf, len, cp);
  va_end(ap);
  
  return buf;
}

/*
 * "lac" vs "list-access" = OK
 * "list" vs "list-access" = OK
 */
int
s_nmatch(const char *a,
	 const char *b,
	 size_t len) {
  int ai, bi, mlen;
  

  ai = bi = 0;
  while (len > 0 && a[ai]) {
    /* For each segment */
    mlen = 0;
    
    while (a[ai] && a[ai] == b[bi]) {
      ++ai;
      ++bi;
      ++mlen;
      --len;
    }
    
    /* At end of 'a' - signal MATCH */
    if (!a[ai])
      return 1;

    /* Segment doesn't match at all -> signal FAIL */
    if (mlen == 0)
      return 0;

    if (a[ai] == '-' || b[bi] != '-') {
      if (a[ai] == '-') {
	++ai;
	--len;
      }
      
      while (b[bi] && b[bi] != '-')
	++bi;
      
      if (!b[bi])
	return a[ai]-b[bi] ? 0 : 1;
    }
    
    ++bi;
  }
  
  return ai ? 1 : 0;
}


SLIST *
slist_new(size_t size) {
  SLIST *sp = malloc(sizeof(*sp));

  if (!sp)
    return NULL;

  sp->c = 0;
  sp->s = size;
  sp->v = malloc(sizeof(char *) * size);
  if (!sp->v) {
    free(sp);
    return NULL;
  }

  return sp;
}


int
slist_add(SLIST *sp,
	  char *s) {

  if (sp->c >= sp->s) {
    char **nv = realloc(sp->v, sizeof(char *) * sp->s + 256);
    if (!nv)
      return -1;

    sp->v = nv;
    sp->s += 256;
  }

  sp->v[sp->c++] = s_dup(s);
  return sp->c;
}


void
slist_free(SLIST *sp) {
  int i;

  for (i = 0; i < sp->c; i++)
    free(sp->v[i]);
  free(sp->v);
  free(sp);
}


char *
slist_join(SLIST *sp,
	   const char *delim) {
  size_t dlen, tlen;
  int i;
  char *buf;
  

  if (sp->c == 0)
    return s_dup("");
  
  dlen = delim ? strlen(delim) : 0;

  tlen = 0;
  for (i = 0; i < sp->c; i++)
    tlen += strlen(sp->v[i]);
  tlen += (sp->c-1)*dlen + 1;

  buf = malloc(tlen);
  if (!buf)
    return NULL;

  s_cpy(buf, tlen, sp->v[0]);
  for (i = 1; i < sp->c; i++) {
    if (delim)
      s_cat(buf, tlen, delim);
    s_cat(buf, tlen, sp->v[i]);
  }

  return buf;
}


int
s_getint(int *ip,
	 char **spp) {
  char *sp;
  int sign = 1;
  
  if (!spp)
    return -1;

  sp = *spp;
  while (isspace(*sp))
    ++sp;

  if (!*sp || !(isdigit(*sp) || *sp == '-')) {
    *spp = sp;
    return 0;
  }

  if (*sp == '-') {
    sign = -1;
    ++sp;
  }
    
  if (sp[0] == '0' && (sp[1] == 'x' || sp[1] == 'X')) {
    sp += 2;
    *ip = 0;

    while (isxdigit(*sp)) {
      unsigned char c = isdigit(*sp) ? *sp - '0' : toupper(*sp)-'A'+10;
      *ip <<= 4;
      *ip |= c;
      ++sp;
    }
  } else {
    *ip = 0;
    
    while (isdigit(*sp)) {
      unsigned char c = *sp - '0';
      *ip *= 10;
      *ip += c;
      ++sp;
    }
  }

  *ip *= sign;
  *spp = sp;
  return 1;
}


int
s_sepint(int *ip,
	    char **spp,
	    char *delim) {
  char *sp;
  int sign = 1;
  
  if (!spp)
    return -1;

  sp = strsep(spp, delim);
  if (!sp)
    return 0;
  
  if (! ((sp[0] == '-' && isdigit(sp[1])) || isdigit(sp[0]))) {
    *spp = sp;
    return 0;
  }
  
  if (*sp == '-') {
    sign = -1;
    ++sp;
  }
  
  if (sp[0] == '0' && (sp[1] == 'x' || sp[1] == 'X')) {
    sp += 2;
    *ip = 0;

    while (isxdigit(*sp)) {
      unsigned char c = isdigit(*sp) ? *sp - '0' : toupper(*sp)-'A'+10;
      *ip <<= 4;
      *ip |= c;
      ++sp;
    }
  } else {
    *ip = 0;
  
    while (isdigit(*sp)) {
      unsigned char c = *sp - '0';
      *ip *= 10;
      *ip += c;
      ++sp;
    }
  }

  *ip *= sign;
  return 1;
}




int
s_cpy(char *dst,
      size_t dstsize,
      const char *src) {
  int i;
  

  if (!dst) {
    errno = EINVAL;
    return -1;
  }

  if (dstsize == 0) {
    errno = ERANGE;
    return -1;
  }
    
  if (!src)
    src = "";

  for (i = 0; src[i] && i < dstsize-1; i++)
    dst[i] = src[i];
  dst[i] = '\0';

  if (src[i]) {
    /* We couldn't fit all data */
    errno = ENOMEM;
    return -1;
  }
  
  return i;
}


int
s_ncpy(char *dst,
       size_t dstsize,
       const char *src,
       size_t len) {
  int i;
  

  if (!dst) {
    errno = EINVAL;
    return -1;
  }

  if (dstsize == 0) {
    errno = ERANGE;
    return -1;
  }
    
  if (!src)
    src = "";

  for (i = 0; src[i] && i < dstsize-1 && i < len; i++)
    dst[i] = src[i];
  dst[i] = '\0';

  if (i < len && src[i]) {
    /* We couldn't fit all data */
    errno = ENOMEM;
    return -1;
  }
  
  return i;
}

int
s_cat(char *dst,
      size_t dstsize,
      const char *src) {
  int i, j;


  if (!dst) {
    errno = EINVAL;
    return -1;
  }

  if (dstsize == 0) {
    errno = ERANGE;
    return -1;
  }
    
  if (!src)
    src = "";

  j = strlen(dst);
  
  for (i = 0; src[i] && j+i < dstsize-1; i++)
    dst[j+i] = src[i];
  dst[j+i] = '\0';

  if (src[i]) {
    /* We couldn't fit all data */
    errno = ENOMEM;
    return -1;
  }
  
  return i+j;
}

int
s_ncat(char *dst,
       size_t dstsize,
       const char *src,
       size_t len) {
  int i, j;


  if (!dst) {
    errno = EINVAL;
    return -1;
  }

  if (dstsize == 0) {
    errno = ERANGE;
    return -1;
  }
    
  if (!src)
    src = "";

  j = strlen(dst);
  
  for (i = 0; src[i] && j+i < dstsize-1 && i < len; i++)
    dst[j+i] = src[i];
  dst[j+i] = '\0';

  if (i < len && src[i]) {
    /* We couldn't fit all data */
    errno = ENOMEM;
    return -1;
  }
  
  return i+j;
}
