/*
 * misc.h
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

#ifndef MISC_H
#define MISC_H 1

#include <sys/types.h>
#include <sys/time.h>
#include <sys/acl.h>
#include <sys/stat.h>

extern char *
s_ndup(const char *s,
       size_t len);

extern char *
s_dup(const char *s);

extern char *
s_cat(const char *s,
      ...);


/*
 * Calculate the difference between two struct timespec, returns elapsed time i microseconds.
 * Also returns the elapsed time and a unit as a string.
 */
extern long
ts_delta(struct timespec *x,
	 const struct timespec *y,
	 long *res,
	 char **unit);


/* 
 * Compare two ACL Entries
 */
extern int
cmp_acl_entry(const void *va,
	      const void *vb);

/* 
 * Compare two ACL Entries - ignore uids & gids
 */
extern int
cmp_acl_entry_sorted(const void *va,
		     const void *vb);

extern int
sort_acl(acl_t a,
	 acl_t *sa);

extern int
is_unsorted_acl(acl_t a);

extern int
merge_permset(acl_permset_t d,
	      acl_permset_t s);

extern int
merge_flagset(acl_flagset_t d,
	      acl_flagset_t s);

extern int
merge_acl(acl_t *a);

extern char *
permset2str(acl_permset_t psp, char *res);

extern char *
flagset2str(acl_flagset_t fsp,
	    char *res);

extern const char *
aet2str(const acl_entry_type_t aet);

extern char *
ace2str(acl_entry_t ae,
	char *rbuf,
	size_t rsize);

extern int
ft_foreach(const char *path,
	   int (*walker)(const char *path,
			 const struct stat *stat,
			 size_t base,
			 size_t level,
			 void *vp),
	   void *vp,
	   size_t maxlevel);

extern int
s_match(const char *a,
	const char *b);

extern int
s_nmatch(const char *a,
	 const char *b,
	 size_t len);

extern int
s_trim(char *s);

#endif
