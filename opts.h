/*
 * opts.h - Options parsing
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

#ifndef OPTS_H
#define OPTS_H 1

#include <stdio.h>
#include <stdarg.h>

#define OPTS_TYPE_NONE 0x0000
#define OPTS_TYPE_UINT 0x0001
#define OPTS_TYPE_INT  0x0002
#define OPTS_TYPE_STR  0x0004

#define OPTS_TYPE_MASK 0x00ff

#define OPTS_TYPE_OPT  0x0100


typedef struct option {
  const char *name;
  char flag;
  unsigned int type;
  int (*handler)(const char *name,
		 const char *vs,
		 unsigned int type,
		 const void *svp,
		 void *dvp,
		 const char *argv0);
  void *dvp;
  const char *help;
} OPTION;


extern int
opts_print(FILE *fp,
	   OPTION *opts,
	   ...);

extern int
opts_parse_argv(int argc,
		char **argv,
		OPTION *opts,
		...);

extern int
opts_set2(OPTION *opts,
	  const char *name,
	  const char *value,
	  const char *argv0);

extern int
opts_set(OPTION *opts,
	 const char *varval,
	 const char *argv0);
#endif
