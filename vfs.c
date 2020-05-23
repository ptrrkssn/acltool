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
#include <sys/types.h>

#if defined(__linux__)
#include <sys/xattr.h>
#elif defined(__FreeBSD__)
#include <sys/extattr.h>
#elif defined(__APPLE__)
#include <sys/xattr.h>
#endif

#define IN_ACLTOOL_VFS_C 1
#include "vfs.h"
#include "misc.h"
#include "gacl.h"

#ifdef ENABLE_SMB
#include "smb.h"
#endif

static char *cwd = NULL;


VFS_TYPE
vfs_get_type(const char *path) {
  char buf[2048];

  
  if (!path) {
    if (!cwd)
      vfs_getcwd(buf, sizeof(buf));
    if (!cwd)
      return VFS_TYPE_UNKNOWN;
  }
  
#ifdef ENABLE_SMB
  if ((path && strncmp(path, "smb://", 6) == 0) ||
      (cwd && (!path || *path != '/') && strncmp(cwd, "smb://", 6) == 0))
    return VFS_TYPE_SMB;
#endif

  return VFS_TYPE_SYS;
}


char *
vfs_getcwd(char *buf,
	   size_t bufsize) {
#ifdef ENABLE_SMB
  if (cwd && strncmp(cwd, "smb://", 6) == 0) {
    if (strlen(cwd)+1 > bufsize) {
      errno = EINVAL;
      return NULL;
    }
    
    strcpy(buf, cwd);
    return buf;
  }
#endif
  
  if (getcwd(buf, bufsize)) {
    if (cwd)
      free(cwd);
    cwd = strdup(buf);
  }

  return buf;
}


char *
vfs_fullpath(const char *path,
	     char *buf,
	     size_t bufsize) {
  size_t len;
  int i;
  
  
  if (!path)
    return vfs_getcwd(buf, bufsize);

  if (*path == '/'
#ifdef ENABLE_SMB
      || strncmp(path, "smb://", 6) == 0
#endif
      ) {
    /* Full path */
    if (strlen(path)+1 > bufsize) {
      errno = ERANGE;
      return NULL;
    }
    strcpy(buf, path);
    return buf;
  }

  if (vfs_getcwd(buf, bufsize) == NULL)
    return NULL;

  if (strcmp(path, ".") == 0)
    return buf;

  len = strlen(buf)+1+strlen(path)+1;
  if (len > bufsize) {
    errno = ERANGE;
    return NULL;
  }

  strcat(buf, "/");
  strcat(buf, path);

  i = 0;
  while (buf[i]) {
    if (strncmp(buf+i, "/./", 3) == 0 || strcmp(buf+i, "/.") == 0) {
      /* Remove "." path segments */
      memmove(buf+i, buf+i+2, strlen(buf+i+2)+1);
    } else if (strncmp(buf+i, "/../", 4) == 0 || strcmp(buf+i, "/..") == 0) {
      /* Remove ".." path segments */
      int j;

      for (j = i-1; j >= 0 && buf[j] != '/'; j--)
	;
      memmove(buf+j, buf+i+3, strlen(buf+i+3)+1);
      i = j;
    } else
      ++i;
  }
    
  return buf;
}

int
vfs_chdir(const char *path) {
  int rc;
  char buf[2048];

  
  if (!path)
    path = "";
  
  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return -1;

    rc = smb_chdir(path);
    if (rc >= 0)
      cwd = strdup(path);
    return rc;
#endif
    
  case VFS_TYPE_SYS:
    rc = chdir(path);
    if (rc >= 0)
      cwd = strdup(path);
    return rc;

  default:
    errno = EINVAL;
    return -1;
  }
}




int
vfs_lstat(const char *path,
	  struct stat *sp) {
  char buf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return -1;
    
    return smb_lstat(buf, sp);
#endif
    
  case VFS_TYPE_SYS:
    if (!path || !*path)
      path = ".";
    return lstat(path, sp);

  default:
    errno = ENOSYS;
    return -1;
  }
}


VFS_DIR *
vfs_opendir(const char *path) {
  VFS_DIR *vdp;
  DIR *dh;
  char buf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return NULL;

    return smb_opendir(buf);
#endif

  case VFS_TYPE_SYS:
    if (!path || !*path)
      path = ".";
    
    dh = opendir(path);
    if (!dh)
      return NULL;
    
    vdp = malloc(sizeof(*vdp));
    if (!vdp)
      return NULL;
    
    vdp->type = VFS_TYPE_SYS;
    vdp->dh.sys = dh;
    return vdp;

    default:
      errno = ENOSYS;
      return NULL;
  }
}


struct dirent *
vfs_readdir(VFS_DIR *vdp) {
  switch (vdp->type) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    return smb_readdir(vdp);
#endif
    
  case VFS_TYPE_SYS:
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
  case VFS_TYPE_SMB:
    rc = smb_closedir(vdp);
    break;
#endif
    
  case VFS_TYPE_SYS:
    rc = closedir(vdp->dh.sys);
    free(vdp);
    break;

  default:
    errno = ENOSYS;
    return -1;
  }
  
  return rc;
}


ssize_t
vfs_listxattr(const char *path,
	      char *buf,
	      size_t bufsize,
	      int flags) {
  char pbuf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, pbuf, sizeof(pbuf)))
      return -1;
    
    return smb_listxattr(pbuf, buf, bufsize);
#endif

  case VFS_TYPE_SYS:
#if defined(__linux__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return llistxattr(path, buf, bufsize);
    return getxattr(path, buf, bufsize);
#elif defined(__FreeBSD__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return extattr_list_link(path, EXTATTR_NAMESPACE_USER, buf, bufsize);
    return extattr_list_file(path, EXTATTR_NAMESPACE_USER, buf, bufsize);
#elif defined(__APPLE__)
    return listxattr(path, buf, bufsize, flags);
#else
    errno = ENOSYS;
    return -1;
#endif    

  default:
    errno = ENOSYS;
    return -1;
  }
}


ssize_t
vfs_getxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize,
	     int flags) {
  char pbuf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, pbuf, sizeof(pbuf)))
      return -1;
    
    return smb_getxattr(pbuf, attr, buf, bufsize);
#endif

  case VFS_TYPE_SYS:
#if defined(__linux__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return lgetxattr(path, attr, buf, bufsize);
    return getxattr(path, attr, buf, bufsize);
#elif defined(__FreeBSD__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return extattr_get_link(path, EXTATTR_NAMESPACE_USER, attr, buf, bufsize);
    return extattr_get_file(path, EXTATTR_NAMESPACE_USER, attr, buf, bufsize);
#elif defined(__APPLE__)
    return getxattr(path, attr, buf, bufsize, flags);
#else
    errno = ENOSYS;
    return -1;
#endif    

  default:
    errno = ENOSYS;
    return -1;
  }
}


ssize_t
vfs_setxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize,
	     int flags) {
  char pbuf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, pbuf, sizeof(pbuf)))
      return -1;
    
    return smb_setxattr(pbuf, attr, buf, bufsize);
#endif

  case VFS_TYPE_SYS:
#if defined(__linux__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return lsetxattr(path, attr, buf, bufsize);
    return setxattr(path, attr, buf, bufsize);
#elif defined(__FreeBSD__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return extattr_set_link(path, EXTATTR_NAMESPACE_USER, attr, buf, bufsize);
    return extattr_set_file(path, EXTATTR_NAMESPACE_USER, attr, buf, bufsize);
#elif defined(__APPLE__)
    return setxattr(path, attr, buf, bufsize, flags);
#else
    errno = ENOSYS;
    return -1;
#endif    

  default:
    errno = ENOSYS;
    return -1;
  }
}


int
vfs_removexattr(const char *path,
		const char *attr,
		int flags) {
  char pbuf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, pbuf, sizeof(pbuf)))
      return -1;
    
    return smb_removexattr(pbuf, attr);
#endif

  case VFS_TYPE_SYS:
#if defined(__linux__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return lremovexattr(path, attr);
    return removexattr(path, attr);
#elif defined(__FreeBSD__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return extattr_delete_link(path, EXTATTR_NAMESPACE_USER, attr);
    return extattr_delete_file(path, EXTATTR_NAMESPACE_USER, attr);
#elif defined(__APPLE__)
    return removexattr(path, attr, flags);
#else
    errno = ENOSYS;
    return -1;
#endif    

  default:
    errno = ENOSYS;
    return -1;
  }
}




GACL *
vfs_acl_get_file(const char *path,
		 GACL_TYPE type) {
  char buf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return NULL;
    
    return smb_acl_get_file(buf);
#endif

  case VFS_TYPE_SYS:
    return gacl_get_file(path, type);

  default:
    errno = ENOSYS;
    return NULL;
  }
}


GACL *
vfs_acl_get_link(const char *path,
		 GACL_TYPE type) {
  char buf[2048];


  switch (vfs_get_type(path)) {
#ifdef ENABLE_SMB
  case VFS_TYPE_SMB:
    puts("SMB-link");
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return NULL;
    
    return smb_acl_get_file(buf);
#endif
    
  case VFS_TYPE_SYS:
    return gacl_get_link_np(path, type);

  default:
    errno = ENOSYS;
    return NULL;
  }
}
