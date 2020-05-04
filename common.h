/*
 * common.h
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

#ifndef COMMON_H
#define COMMON_H

typedef enum acl_style
  {
   ACL_STYLE_DEFAULT  = 0x00,
   ACL_STYLE_STANDARD = 0x01,
   ACL_STYLE_BRIEF    = 0x02,
   ACL_STYLE_VERBOSE  = 0x03,
   ACL_STYLE_CSV      = 0x10,
   ACL_STYLE_SAMBA    = 0x20,
   ACL_STYLE_ICACLS   = 0x30,
   ACL_STYLE_SOLARIS  = 0x40,
   ACL_STYLE_PRIMOS   = 0x50,
  } ACL_STYLE;


extern acl_t 
get_acl(const char *path, 
	const struct stat *sp);

extern int
print_ace(acl_t ap,
	  int p,
	  int verbose);

extern int
set_acl(const char *path,
	const struct stat *sp,
	acl_t ap,
	acl_t oap);

extern int
str2filetype(const char *str,
	     mode_t *f_filetype);


extern int
print_acl(FILE *fp,
	  acl_t a,
	  const char *path,
	  const struct stat *sp);


extern int
str2style(const char *str,
	  ACL_STYLE *sp);

extern const char *
style2str(ACL_STYLE s);

extern char *
mode2str(mode_t m);

extern int
aclcmd_foreach(int argc,
	       char **argv,
	       int (*handler)(const char *path,
			      const struct stat *sp,
			      size_t base,
			      size_t level,
			      void *vp),
	       void *vp);

extern char *
mode2typestr(mode_t m);

#endif
