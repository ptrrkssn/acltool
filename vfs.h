/*
 * vfs.h
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

#ifndef ACLTOOL_VFS_H
#define ACLTOOL_VFS_H

#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef struct {
  enum { VFS_DIR_TYPE_UNKNOWN = 0, VFS_DIR_TYPE_SYS = 1, VFS_DIR_TYPE_SMB = 2 } type;
  union {
    DIR *sys;
    int smb;
  } dh;
} VFS_DIR;


extern int
vfs_chdir(const char *path);

extern char *
vfs_getcwd(char *buf,
	   size_t bufsize);

extern char *
vfs_fullpath(const char *path,
	     char *buf,
	     size_t bufsize);

extern int
vfs_lstat(const char *path,
	  struct stat *sp);

extern VFS_DIR *
vfs_opendir(const char *path);

extern struct dirent *
vfs_readdir(VFS_DIR *dp);

extern int
vfs_closedir(VFS_DIR *dp);


#ifndef IN_ACLTOOL_VFS_C
#define chdir    vfs_chdir
#define getcwd   vfs_getcwd
#define lstat    vfs_lstat
#define opendir  vfs_opendir
#define readdir  vfs_readdir
#define closedir vfs_closedir
#define DIR      VFS_DIR
#endif

#endif
