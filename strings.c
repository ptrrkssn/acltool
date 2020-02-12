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

#include "misc.h"

#define NEW(vp) ((vp) = malloc(sizeof(*(vp))))


char *
s_ndup(const char *s,
       size_t len)
{
  char *rs;
  
  
  if (!s)
    return NULL;
  
  rs = malloc(len+1);
  if (!rs)
    return NULL;
  
  strncpy(rs, s, len);
  rs[len] = '\0';
  
  return rs;
}

char *
s_dup(const char *s)
{
  if (!s)
    return NULL;
  
  return strdup(s);
}

char *
s_cat(const char *s,
      ...) {
  char *res, *cp;
  size_t len;
  va_list ap;
  
  
  va_start(ap, s);
  len = strlen(s);
  while ((cp = va_arg(ap, char *)) != NULL)
    len += strlen(cp);
  va_end(ap);

  res = malloc(len+1);
  if (!res)
    return NULL;
  
  strcpy(res, s);
  va_start(ap, s);
  while ((cp = va_arg(ap, char *)) != NULL)
    strcat(res, cp);
  va_end(ap);

  return res;
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

