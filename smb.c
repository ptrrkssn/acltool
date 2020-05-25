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
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/statvfs.h>

#include "strings.h"
#include "vfs.h"
#include "smb.h"

#if ENABLE_SMB
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



/* Data via extended attributes
 *                     system.nt_sec_desc.<attribute name>
 *                     system.nt_sec_desc.*
 *                     system.nt_sec_desc.*+
 *
 *                  where <attribute name> is one of:
 *
 *                     revision
 *                     owner
 *                     owner+
 *                     group
 *                     group+
 *                     acl:<name or sid>
 *                     acl+:<name or sid>
 */

int
smb_lstat(const char *path,
	  struct stat *sp) {
  const char *owner_attr = "system.nt_sec_desc.owner+";
  const char *group_attr = "system.nt_sec_desc.group+";
  char buf[256];
  int rc;
  struct passwd *pp;
  struct group *gp;
  

  _smb_init();
  
  rc = smbc_stat(path, sp);
  if (rc < 0)
    return rc;

  /*
   * Hack to override the st_uid & st_gid with the real owner & group 
   */
  if (smb_getxattr(path, owner_attr, buf, sizeof(buf)) < 0)
    return -1;
  pp = getpwnam(buf);
  if (!pp) {
    int i;
    for (i = 0; buf[i]; i++)
      buf[i] = tolower(buf[i]);
    pp = getpwnam(buf);
  }
  if (pp)
    sp->st_uid = pp->pw_uid;
  
  if (smb_getxattr(path, group_attr, buf, sizeof(buf)) < 0)
    return -1;

  gp = getgrnam(buf);
  if (!gp) {
    int i;
    for (i = 0; buf[i]; i++)
      buf[i] = tolower(buf[i]);
    gp = getgrnam(buf);
  }
    
  if (gp)
    sp->st_gid = gp->gr_gid;

  return rc;
}


int
smb_statvfs(const char *path,
	    struct statvfs *sp) {
  
  _smb_init();
  
  return smbc_statvfs((char *) path, sp);
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

  dep->d_reclen = sizeof(*dep);
#if defined(__FreeBSD__) || defined(DT_DIR)
  dep->d_fileno = 0;
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
#endif

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
		const char *attr) {
  _smb_init();
  
  return smbc_removexattr(path, attr);
}


/*
  AD\peter86:0/11/0x001e01ff
  AD\employee-liu.se:0/3/0x00120088
  \Everyone:0/11/0x00120088
  AD\peter86:0/0/0x001e01ff
  AD\Domain_Users:0/0/0x001200a9
  \Everyone:0/0/0x001200a9
*/

GACL *
smb_acl_get_file(const char *path) {
  char buf[2048], *bp, *cp;
  const char *aclattr = "system.nt_sec_desc.acl.*+";
  GACL *ap;
  int n_ace;


  if (smb_getxattr(path, aclattr, buf, sizeof(buf)) < 0)
    return NULL;

  n_ace = 1;
  for (bp = buf; *bp; bp++)
    if (*bp == ',')
      ++n_ace;
  
  ap = gacl_init(n_ace);
  if (!ap)
    return NULL;
		 
  bp = buf;
  while ((cp = strsep(&bp, ",")) != NULL) {
    char *s_realm = strsep(&cp, "\\");
    char *s_user  = strsep(&cp, ":");
    char *s_type  = strsep(&cp, "/");
    char *s_flags = strsep(&cp, "/");
    char *s_perms = strsep(&cp, "/");
    int type, flags, perms;
    GACE *ep = NULL;
    struct passwd *pp;
    struct group *gp;
    GACE_PERMSET ps;
    GACE_FLAGSET fs;
    GACE_TAG_TYPE e_type;
    uid_t e_ugid;
    char *e_name;
    
    
    if (!s_realm || !s_user  || !*s_user ||
	!s_type  || sscanf(s_type, "%d", &type) != 1 ||
	!s_flags || sscanf(s_flags, "%d", &flags) != 1 ||
	!s_perms || sscanf(s_perms, "0x%x", &perms) != 1)
      continue; /* Invalid entry - skip */

    e_type = -1;
    e_ugid = -1;
    e_name = NULL;
    
    if (!*s_realm && strcmp(s_user, "Everyone") == 0) {
      e_type = GACE_TAG_TYPE_EVERYONE;
      e_name = s_dup("everyone@");
    }
    else {
      if (!s_realm) /* XXX TODO: Check realm */
	continue;
      
      pp = getpwnam(s_user);
      gp = getgrnam(s_user);

      if (pp && gp) { /* Name matches both user and group */
	errno = EINVAL;
	return NULL;
      }

      if (!pp && !gp) /* Skip unknown users */
	continue; 

      if (pp) {
	e_type = GACE_TAG_TYPE_USER;
	e_ugid = pp->pw_uid;
      } else {
	e_type = GACE_TAG_TYPE_GROUP;
	e_ugid = gp->gr_gid;
      }
      
      if (s_realm && *s_realm)
	e_name = s_dupcat(s_realm, "\\", s_user, NULL);
      else
	e_name = s_dup(s_user);
    }
    
    if (gacl_create_entry(&ap, &ep) < 0)
      goto Fail;

    ep->tag.type = e_type;
    ep->tag.ugid = e_ugid;
    ep->tag.name = e_name;
    
    switch (type) {
    case SMB_ACL_TYPE_ALLOW:
      gacl_set_entry_type_np(ep, GACE_TYPE_ALLOW);
      break;
    case SMB_ACL_TYPE_DENY:
      gacl_set_entry_type_np(ep, GACE_TYPE_DENY);
      break;
    case SMB_ACL_TYPE_AUDIT:
      gacl_set_entry_type_np(ep, GACE_TYPE_AUDIT);
      break;
    case SMB_ACL_TYPE_ALARM:
      gacl_set_entry_type_np(ep, GACE_TYPE_ALARM);
      break;
    default:
      errno = EINVAL;
      goto Fail;
    }

    gacl_clear_flags_np(&fs);
    if (flags & SMB_ACL_FLAG_OI)
      gacl_add_flag_np(&fs, GACE_FLAG_FILE_INHERIT);
    if (flags & SMB_ACL_FLAG_CI)
      gacl_add_flag_np(&fs, GACE_FLAG_DIRECTORY_INHERIT);
    if (flags & SMB_ACL_FLAG_NI)
      gacl_add_flag_np(&fs, GACE_FLAG_NO_PROPAGATE_INHERIT);
    if (flags & SMB_ACL_FLAG_IO)
      gacl_add_flag_np(&fs, GACE_FLAG_INHERIT_ONLY);
    gacl_set_flagset_np(ep, &fs);
    
    gacl_clear_perms(&ps);
    if (perms & SMB_ACL_PERM_RD)
      gacl_add_perm(&ps, GACE_READ_DATA);
    if (perms & SMB_ACL_PERM_WD)
      gacl_add_perm(&ps, GACE_WRITE_DATA);
    if (perms & SMB_ACL_PERM_X)
      gacl_add_perm(&ps, GACE_EXECUTE);
    if (perms & SMB_ACL_PERM_AD)
      gacl_add_perm(&ps, GACE_APPEND_DATA);
    if (perms & SMB_ACL_PERM_REA)
      gacl_add_perm(&ps, GACE_READ_NAMED_ATTRS);
    if (perms & SMB_ACL_PERM_WEA)
      gacl_add_perm(&ps, GACE_WRITE_NAMED_ATTRS);
    if (perms & SMB_ACL_PERM_DC)
      gacl_add_perm(&ps, GACE_DELETE_CHILD);
    if (perms & SMB_ACL_PERM_D)
      gacl_add_perm(&ps, GACE_DELETE);
    if (perms & SMB_ACL_PERM_RA)
      gacl_add_perm(&ps, GACE_READ_ATTRIBUTES);
    if (perms & SMB_ACL_PERM_WA)
      gacl_add_perm(&ps, GACE_WRITE_ATTRIBUTES);
    
    if (perms & SMB_ACL_PERM_RC)
      gacl_add_perm(&ps, GACE_READ_ACL);
    if (perms & SMB_ACL_PERM_WDAC)
      gacl_add_perm(&ps, GACE_WRITE_ACL);
    if (perms & SMB_ACL_PERM_WO)
      gacl_add_perm(&ps, GACE_WRITE_OWNER);
    if (perms & SMB_ACL_PERM_S)
      gacl_add_perm(&ps, GACE_SYNCHRONIZE);
    
    gacl_set_permset(ep, &ps);
  }

  return ap;
  
 Fail:
  gacl_free(ap);
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
	     size_t bufsize) {
  errno = ENOSYS;
  return -1;
}

GACL *
smb_acl_get_file(const char *path) {
  errno = ENOSYS;
  return NULL;
}

#endif
