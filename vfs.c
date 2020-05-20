/*
 * vfs.c
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
#include <errno.h>

#define IN_ACLTOOL_VFS_C 1
#include "vfs.h"
#include "misc.h"

#ifdef ENABLE_SMB
#include "smb.h"
#endif

static char *cwd = NULL;


int
vfs_chdir(const char *path) {
  int rc;


  if (!path)
    path = "";

#ifdef ENABLE_SMB
  if (strncmp(path, "smb:/", 5) == 0) {
    rc = smb_chdir(path);
    if (rc >= 0)
    cwd = strdup(path);
    return rc;
  }
  
  if (*path != '/' && cwd && strncmp(cwd, "smb:/", 5) == 0) {
    char *np;
    
    if (strcmp(path, "..") == 0) {
      np = strrchr(cwd, '/');
      if (np)
	*np = '\0';
      return smb_chdir(cwd);
    } else {
      np = strxcat(cwd, *path ? "/" : NULL, path, NULL);
      if (!np)
	return -1;
      rc = smb_chdir(np);
      cwd = np;
      return rc;
    }
  }
#endif
  if (!path || !*path)
    path = ".";
  
  rc = chdir(path);
  if (rc >= 0)
    cwd = strdup(path);

  return rc;
}


char *
vfs_getcwd(char *buf,
	   size_t bufsize) {
#ifdef ENABLE_SMB
  if (cwd && strncmp(cwd, "smb:/", 5) == 0) {
    if (strlen(cwd)+1 > bufsize) {
      errno = EINVAL;
      return NULL;
    }
    
    strcpy(buf, cwd);
    return buf;
  }
#endif
  
  return getcwd(buf, bufsize);
}


int
vfs_lstat(const char *path,
	  struct stat *sp) {
  if (!path)
    path = "";
  
#ifdef ENABLE_SMB
  if (strncmp(path, "smb:/", 5) == 0)
    return smb_lstat(path, sp);
  
  if (*path != '/' && cwd && strncmp(cwd, "smb:/", 5) == 0) {
    int rc;
    char *np = strxcat(cwd, *path ? "/" : NULL, path, NULL);
    if (!np)
      return -1;
    rc = smb_lstat(np, sp);
    free(np);
    return rc;
  }
#endif

  if (!path || !*path)
    path = ".";
  
  return lstat(path, sp);
}


VFS_DIR *
vfs_opendir(const char *path) {
  VFS_DIR *vdp;
  DIR *dh;

  if (!path)
    path = "";
  
#ifdef ENABLE_SMB
  if (strncmp(path, "smb:/", 5) == 0)
    return smb_opendir(path);
  
  if (*path != '/' && cwd && strncmp(cwd, "smb:/", 5) == 0) {
    char *np = strxcat(cwd, *path ? "/" : NULL, path, NULL);
    if (!np)
      return NULL;
    vdp = smb_opendir(np);
    free(np);
    return vdp;
  }
#endif
  
  if (!path || !*path)
    path = ".";
  
  dh = opendir(path);
  if (!dh)
    return NULL;
  
  vdp = malloc(sizeof(*vdp));
  if (!vdp)
    return NULL;
  
  vdp->type = VFS_DIR_TYPE_SYS;
  vdp->dh.sys = dh;
  return vdp;
}


struct dirent *
vfs_readdir(VFS_DIR *vdp) {
  switch (vdp->type) {
#ifdef ENABLE_SMB
  case VFS_DIR_TYPE_SMB:
    return smb_readdir(vdp);
#endif
  case VFS_DIR_TYPE_SYS:
    return readdir(vdp->dh.sys);
    
  default:
    errno = ENOSYS;
    return NULL;
  }
}


int
vfs_closedir(VFS_DIR *vdp) {
  int rc;

  
  switch (vdp->type) {
#ifdef ENABLE_SMB
  case VFS_DIR_TYPE_SMB:
    rc = smb_closedir(vdp);
    break;
#endif
  case VFS_DIR_TYPE_SYS:
    rc = closedir(vdp->dh.sys);
    free(vdp);
    break;

  default:
    errno = ENOSYS;
    return -1;
  }
  
  return rc;
}

