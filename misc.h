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
#include <sys/stat.h>

#include "acltool.h"


/*
 * Calculate the difference between two struct timespec, returns elapsed time i microseconds.
 * Also returns the elapsed time and a unit as a string.
 */
extern long
ts_delta(struct timespec *x,
	 const struct timespec *y,
	 long *res,
	 char **unit);


extern char *
permset2str(acl_permset_t psp, char *res);

extern char *
flagset2str(acl_flagset_t fsp,
	    char *res);

extern const char *
aet2str(gacl_entry_type_t aet);

extern char *
ace2str(acl_entry_t ae,
	char *rbuf,
	size_t rsize);

extern char *
ace2str_samba(acl_entry_t ae,
	      char *rbuf,
	      size_t rsize,
	      const struct stat *sp);

extern char *
ace2str_icacls(acl_entry_t ae,
	       char *rbuf,
	       size_t rsize,
	       const struct stat *sp);

extern int
ft_foreach(const char *path,
	   int (*walker)(const char *path,
			 const struct stat *stat,
			 size_t base,
			 size_t level,
			 void *vp),
	   void *vp,
	   size_t maxlevel,
	   mode_t filetypes);


extern int
prompt_user(char *buf,
	    size_t bufsize,
	    int echo,
	    const char *prompt,
	    ...);

#endif
