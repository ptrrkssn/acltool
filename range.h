/*
 * range.h - Range handling code
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

#ifndef RANGE_H
#define RANGE_H 1

#include <stdio.h>
#include <limits.h>

typedef struct range {
  int min;
  int max;
  struct range *next;
} RANGE;

#define RANGE_NONE (INT_MIN)
#define RANGE_MAX  (INT_MAX-1)
#define RANGE_END  (INT_MAX)

extern int
range_len(RANGE *rp);

extern int
range_first(RANGE *rp, int *p);

extern int
range_last(RANGE *rp, int *p);

extern int
range_next(RANGE *rp, int *pp);

extern int
range_prev(RANGE *rp, int *pp);

extern int
range_add(RANGE **rp, int p1, int p2);

extern int
range_addn(RANGE **rp, int p, int len);

extern int
range_adds(RANGE **rp, const char **sp);

extern int
range_print(RANGE *rp, FILE *fp);

extern void
range_free(RANGE **rpp);

#endif
