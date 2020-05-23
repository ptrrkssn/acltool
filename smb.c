/*
 * smb.c
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

#include "vfs.h"

#ifdef ENABLE_SMB
#include <libsmbclient.h>

static SMBCCTX *context = NULL;


static void
get_auth_data_with_context_fn(SMBCCTX *context,
			      const char * pServer,
			      const char * pShare,
			      char * pWorkgroup,
			      int maxLenWorkgroup,
			      char * pUsername,
			      int maxLenUsername,
			      char * pPassword,
			      int maxLenPassword)
{
  return;
}  



static int
_smb_init(void) {
  if (context)
    return 0;

  context = smbc_new_context();
  if (!context) {
    printf("Could not allocate new smbc context\n");
    return -1;
  }
  
  smbc_setFunctionAuthDataWithContext(context,
				      get_auth_data_with_context_fn);
  
  smbc_setOptionUserData(context, strdup("hello world"));
  smbc_setOptionUseKerberos(context, 1);
  smbc_setOptionFallbackAfterKerberos(context, 1);

    if (!smbc_init_context(context)) {
        smbc_free_context(context, 0);
        printf("Could not initialize smbc context\n");
        return -1;
    }

    /* Tell the compatibility layer to use this context */
    smbc_set_context(context);

    return 1;
}


int
smb_lstat(const char *path,
	  struct stat *sp) {
  _smb_init();
  
  return smbc_stat(path, sp);
}


int
smb_chdir(const char *path) {
  struct stat sb;

  
  if (smb_lstat(path, &sb) < 0)
    return -1;

  if (!S_ISDIR(sb.st_mode)) {
    errno = EINVAL;
    return -1;
  }
    
  return 0;
}



VFS_DIR *
smb_opendir(const char *path) {
  int dh;
  struct stat sb;
  VFS_DIR *vdp;
  

  if (smb_lstat(path, &sb) < 0)
    return NULL;

  if (!S_ISDIR(sb.st_mode)) {
    errno = EINVAL;
    return NULL;
  }
    
  dh = smbc_opendir(path);
  if (dh < 0)
    return NULL;

  vdp = malloc(sizeof(*vdp));
  if (!vdp) {
    smbc_closedir(dh);
    return NULL;
  }

  vdp->type = VFS_TYPE_SMB;
  vdp->dh.smb = dh;
  return vdp;
}


struct dirent *
smb_readdir(VFS_DIR *vdp) {
  struct smbc_dirent *sdep;
  struct dirent *dep;
  int dh;
  

  if (vdp->type != VFS_TYPE_SMB) {
    errno = EINVAL;
    return NULL;
  }
  
  dh = vdp->dh.smb;

  do {
    sdep = smbc_readdir(dh);
    if (!sdep)
      return NULL;
  } while (sdep->smbc_type != SMBC_DIR && sdep->smbc_type != SMBC_FILE && sdep->smbc_type != SMBC_LINK);

  dep = malloc(sizeof(*dep));
  if (!dep)
    return NULL;

  dep->d_fileno = 0;
  dep->d_reclen = sizeof(*dep);
  switch (sdep->smbc_type) {
  case SMBC_DIR:
    dep->d_type = DT_DIR;
    break;
  case SMBC_FILE:
    dep->d_type = DT_REG;
    break;
  case SMBC_LINK:
    dep->d_type = DT_LNK;
    break;
  }
  strcpy(dep->d_name, sdep->name); /* XXX: Check name length */
  return dep;
}


int
smb_closedir(VFS_DIR *vdp) {
  int dh;
  

  if (vdp->type != VFS_TYPE_SMB) {
    errno = EINVAL;
    return -1;
  }
  
  dh = vdp->dh.smb;

  memset(vdp, 0, sizeof(*vdp));
  free(vdp);
  
  return smbc_closedir(dh);
}


int
smb_listxattr(const char *path,
	      char *buf,
	      size_t bufsize,
	      int flags) {
  errno = ENOSYS;
  return -1;
}

int
smb_getxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize) {
  _smb_init();
  
  return smbc_getxattr(path, attr, buf, bufsize);
}

int
smb_setxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize) {
  _smb_init();
  
  return smbc_setxattr(path, attr, buf, bufsize, 0);
}

int
smb_removexattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize) {
  _smb_init();
  
  return smbc_removexattr(path, attr);
}


GACL *
smb_acl_get_file(const char *path) {
  char buf[2048];


  if (smb_getxattr(path, "system.nt_sec_desc.acl.*+", buf, sizeof(buf)) < 0)
    return NULL;

  fprintf(stderr, "SMB ACL:\t%s\n", buf);
  /* Translate value into standard GACL */

  errno = ENOSYS;
  return NULL;
}

#else

int
smb_lstat(const char *path,
	  struct stat *sp) {
  errno = ENOSYS;
  return -1;
}

int
smb_chdir(const char *path) {
  errno = ENOSYS;
  return -1;
}

VFS_DIR *
smb_opendir(const char *path) {
  errno = ENOSYS;
  return NULL;
}

struct dirent *
smb_readdir(VFS_DIR *vdp) {
  errno = ENOSYS;
  return NULL;
}

int
smb_closedir(VFS_DIR *vdp) {
  errno = ENOSYS;
  return -1;
}

int
smb_listxattr(const char *path,
	      char *buf,
	      size_t bufsize,
	      int flags) {
  errno = ENOSYS;
  return -1;
}

int
smb_getxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize,
	     int flags) {
  errno = ENOSYS;
  return -1;
}

GACL *
smb_acl_get_file(const char *path) {
  errno = ENOSYS;
  return NULL;
}

#endif
