/*
 * vfs.c - A "virtual" filesystem layer allowing protocol://path stuff
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
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#if defined(__linux__)
#include <sys/xattr.h>
#elif defined(__FreeBSD__)
#include <sys/extattr.h>
#elif defined(__APPLE__)
#include <sys/xattr.h>
#elif defined(__sun__)
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#endif

#define IN_ACLTOOL_VFS_C 1
#include "vfs.h"

#include "gacl.h"

#if HAVE_LIBSMBCLIENT
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
  
#if HAVE_LIBSMBCLIENT
  if ((path && strncmp(path, "smb://", 6) == 0) ||
      (cwd && (!path || *path != '/') && strncmp(cwd, "smb://", 6) == 0))
    return VFS_TYPE_SMB;
#endif

  return VFS_TYPE_SYS;
}


char *
vfs_getcwd(char *buf,
	   size_t bufsize) {
#if HAVE_LIBSMBCLIENT
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
#if HAVE_LIBSMBCLIENT
      || strncmp(path, "smb://", 6) == 0
#endif
      ) {
    /* Full path */
    if (strlen(path)+1 > bufsize) {
      errno = ERANGE;
      return NULL;
    }
    strcpy(buf, path);
#if 0
    return buf;
#endif
  } else {

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
  }

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
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif
  
  if (!path)
    path = "";
  
  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif

  memset(sp, 0, sizeof(*sp));
  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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


int
vfs_statvfs(const char *path,
	    struct statvfs *sp) {
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return -1;
    
    return smb_statvfs(buf, sp);
#endif
    
  case VFS_TYPE_SYS:
    if (!path || !*path)
      path = ".";
    return statvfs(path, sp);

  default:
    errno = ENOSYS;
    return -1;
  }
}



VFS_DIR *
vfs_opendir(const char *path) {
  VFS_DIR *vdp;
  DIR *dh;
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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
#if HAVE_LIBSMBCLIENT
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
#if HAVE_LIBSMBCLIENT
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


int
vfs_str2xattrflags(const char *s,
		   int *flags) {
  *flags = 0;
  
  while (*s)
    switch (*s++) {
    case 'f':
      *flags |= VFS_XATTR_FLAG_NOFOLLOW;
      break;
      
#if defined(__FreeBSD__)
    case 'S':
      *flags |= VFS_XATTR_FLAG_SYSTEM;
      break;
#endif
      
#if defined(__APPLE__)
    case 'C':
      *flags |= VFS_XATTR_FLAG_COMPRESSION;
      break;
#endif
    default:
      errno = EINVAL;
      return -1;
    }

  return 0;
}


ssize_t
vfs_listxattr(const char *path,
	      char *buf,
	      size_t bufsize,
	      int flags) {
#if HAVE_LIBSMBCLIENT
  char pbuf[2048];
#endif
#if defined(__FreeBSD__)
  char tbuf[2048], *tp;
  int tlen, rc;
#endif
#if defined(__sun__)
  int fd;
  DIR *dirp;
  struct dirent *dp;
  size_t tlen, len;
#endif
  

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, pbuf, sizeof(pbuf)))
      return -1;
    
    return smb_listxattr(pbuf, buf, bufsize, 0);
#endif

  case VFS_TYPE_SYS:
#if defined(__linux__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return llistxattr(path, buf, bufsize);
    return listxattr(path, buf, bufsize);
#elif defined(__FreeBSD__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      rc = extattr_list_link(path,
			     (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			     tbuf, sizeof(tbuf));
    else
      rc = extattr_list_file(path,
			     (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			     tbuf, sizeof(tbuf));
    if (rc < 0)
      return rc;

    tlen = 0;
    tp = tbuf;
    while (rc > 0) {
      int elen = * (unsigned char *) tp;

      if (tlen + elen + 1 > bufsize) {
	errno = ERANGE;
	return -1;
      }

      memcpy(buf+tlen, tp+1, elen);
      buf[tlen+elen] = '\0';

      ++elen;
      tp += elen;
      rc -= elen;
      tlen += elen;
    }
    return tlen;
#elif defined(__APPLE__)
    return listxattr(path, buf, bufsize, flags);
#elif defined(__sun__)
    fd = attropen(path, ".", O_RDONLY);
    if (fd < 0)
      return -1;

    dirp = fdopendir(fd);
    tlen = 0;
    while ((dp = readdir(dirp)) != NULL) {
      if (strcmp(dp->d_name, ".") == 0 ||
	  strcmp(dp->d_name, "..") == 0)
	continue;
      
      len = strlen(dp->d_name);
      if (tlen+len+1 > bufsize) {
	closedir(dirp);
	errno = ERANGE;
	return -1;
      }
      strcpy(buf+tlen, dp->d_name);
      tlen += len+1;
    }
    closedir(dirp);
    return tlen;
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
#if HAVE_LIBSMBCLIENT
  char pbuf[2048];
#endif
#if defined(__sun__)
  int fd;
  size_t len;
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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
      return extattr_get_link(path,
			      (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			      attr, buf, bufsize);
    return extattr_get_file(path,
			    (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			    attr, buf, bufsize);
#elif defined(__APPLE__)
    return getxattr(path, attr, buf, bufsize, 0, flags);
#elif defined(__sun__)
    fd = attropen(path, attr, O_RDONLY);
    if (fd < 0)
      return -1;

    len = read(fd, buf, bufsize);
    close(fd);
    return len;
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
#if HAVE_LIBSMBCLIENT
  char pbuf[2048];
#endif
#if defined(__sun__)
  int fd;
  size_t len;
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, pbuf, sizeof(pbuf)))
      return -1;
    
    return smb_setxattr(pbuf, attr, buf, bufsize);
#endif

  case VFS_TYPE_SYS:
#if defined(__linux__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return lsetxattr(path, attr, buf, bufsize, 0);
    return setxattr(path, attr, buf, bufsize, 0);
#elif defined(__FreeBSD__)
    if (flags & VFS_XATTR_FLAG_NOFOLLOW)
      return extattr_set_link(path,
			      (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			      attr, buf, bufsize);
    return extattr_set_file(path,
			    (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			    attr, buf, bufsize);
#elif defined(__APPLE__)
    return setxattr(path, attr, buf, bufsize, 0, flags);
#elif defined(__sun__)
    fd = attropen(path, attr, O_CREAT|O_WRONLY, 0600);
    if (fd < 0)
      return -1;

    len = write(fd, buf, bufsize);
    close(fd);
    return len;
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
#if HAVE_LIBSMBCLIENT
  char pbuf[2048];
#endif
#if defined(__sun__)
  int fd, rc;
#endif
  
  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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
      return extattr_delete_link(path,
				 (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
				 attr);
    return extattr_delete_file(path,
			       (flags & VFS_XATTR_FLAG_SYSTEM ? EXTATTR_NAMESPACE_SYSTEM : EXTATTR_NAMESPACE_USER),
			       attr);
#elif defined(__APPLE__)
    return removexattr(path, attr, flags);
#elif defined(__sun__)
    if (*attr == '/') {
      errno = EINVAL;
      return -1;
    }
      
    fd = attropen(path, ".", O_RDONLY);
    if (fd < 0) {
      puts("FOO");
      return -1;
    }

    rc = unlinkat(fd, attr, 0);
    close(fd);
    return rc;
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
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
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


int
vfs_acl_set_file(const char *path,
		 GACL_TYPE type,
		 GACL *ap) {
#if HAVE_LIBSMBCLIENT
  char buf[2048];
#endif

  switch (vfs_get_type(path)) {
#if HAVE_LIBSMBCLIENT
  case VFS_TYPE_SMB:
    if (!vfs_fullpath(path, buf, sizeof(buf)))
      return -1;
    
    return smb_acl_set_file(buf, ap);
#endif

  case VFS_TYPE_SYS:
    return gacl_set_file(path, type, ap);

  default:
    errno = ENOSYS;
    return -1;
  }
}


