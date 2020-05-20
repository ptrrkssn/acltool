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
_smb_get_auth_data_fn(const char * pServer,
		      const char * pShare,
		      char * pWorkgroup,
		      int maxLenWorkgroup,
		      char * pUsername,
		      int maxLenUsername,
		      char * pPassword,
		      int maxLenPassword)
{
    char            temp[128];
    char            server[256] = { '\0' };
    char            share[256] = { '\0' };
    char            workgroup[256] = { '\0' };
    char            username[256] = { '\0' };
    char            password[256] = { '\0' };
    char           *ret;

    static int krb5_set = 1;

    if (strcmp(server, pServer) == 0 &&
        strcmp(share, pShare) == 0 &&
        *workgroup != '\0' &&
        *username != '\0')
    {
        strncpy(pWorkgroup, workgroup, maxLenWorkgroup - 1);
        strncpy(pUsername, username, maxLenUsername - 1);
        strncpy(pPassword, password, maxLenPassword - 1);
        return;
    }

    if (krb5_set && getenv("KRB5CCNAME")) {
      krb5_set = 0;
      return;
    }

    fprintf(stdout, "Workgroup: [%s] ", pWorkgroup);
    ret = fgets(temp, sizeof(temp), stdin);
    if (ret == NULL) {
	    return;
    }
    
    if (temp[strlen(temp) - 1] == '\n') /* A new line? */
    {
        temp[strlen(temp) - 1] = '\0';
    }
    
    if (temp[0] != '\0')
    {
        strncpy(pWorkgroup, temp, maxLenWorkgroup - 1);
    }
    
    fprintf(stdout, "Username: [%s] ", pUsername);
    ret = fgets(temp, sizeof(temp), stdin);
    if (ret == NULL) {
	    return;
    }
    
    if (temp[strlen(temp) - 1] == '\n') /* A new line? */
    {
        temp[strlen(temp) - 1] = '\0';
    }
    
    if (temp[0] != '\0')
    {
        strncpy(pUsername, temp, maxLenUsername - 1);
    }
    
    fprintf(stdout, "Password: ");
    ret = fgets(temp, sizeof(temp), stdin);
    if (ret == NULL) {
	    return;
    }
    
    if (temp[strlen(temp) - 1] == '\n') /* A new line? */
    {
        temp[strlen(temp) - 1] = '\0';
    }
    
    if (temp[0] != '\0')
    {
        strncpy(pPassword, temp, maxLenPassword - 1);
    }

    strncpy(workgroup, pWorkgroup, sizeof(workgroup) - 1);
    strncpy(username, pUsername, sizeof(username) - 1);
    strncpy(password, pPassword, sizeof(password) - 1);

    krb5_set = 1;
}


static void
_smb_init(void) {
  if (context)
    return;
  
  if (smbc_init(_smb_get_auth_data_fn, 0) < 0)
    return;
  
  context = smbc_set_context(NULL);
  if (context) {
    smbc_setOptionFullTimeNames(context, 1);
  }
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

  vdp->type = VFS_DIR_TYPE_SMB;
  vdp->dh.smb = dh;
  return vdp;
}


struct dirent *
smb_readdir(VFS_DIR *vdp) {
  struct smbc_dirent *sdep;
  struct dirent *dep;
  int dh;
  

  if (vdp->type != VFS_DIR_TYPE_SMB) {
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
  

  if (vdp->type != VFS_DIR_TYPE_SMB) {
    errno = EINVAL;
    return -1;
  }
  
  dh = vdp->dh.smb;

  memset(vdp, 0, sizeof(*vdp));
  free(vdp);
  
  return smbc_closedir(dh);
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

#endif
