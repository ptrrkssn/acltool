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

#include "config.h"

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

#if HAVE_LIBSMBCLIENT
#include <libsmbclient.h>
#include "misc.h"

#if !defined(SMBC_XATTR_FLAG_NO_ACL_SORT)
#warning Missing Samba ACL-Set-Sorting patch detected (see README)
#endif

static SMBCCTX *context = NULL;

static int _smb_flags = 0;


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
  static char *saved_password = NULL;

#if 0
  fprintf(stderr, "pServer=%s, pShare=%s, pWorkgroup=%s, pUsername=%s, pPassword=%s\n",
	  pServer, pShare, pWorkgroup, pUsername, pPassword);
#endif
  
  if (_smb_flags & SMB_PROMPT_PASSWORD) {
    if (saved_password)
      strncpy(pPassword, saved_password, maxLenPassword);
    else 
      if (prompt_user(pPassword, maxLenPassword, 0, "%s\\%s's Password: ", pWorkgroup, pUsername) > 0)
	saved_password = s_dup(pPassword);
  }
  
  return;
}  


void
smb_init(int flags) {
  _smb_flags = flags;
}


static int
_smb_init(void) {
  if (context)
    return 0;

  context = smbc_new_context();
  if (!context)
    return -1;
  
  smbc_setFunctionAuthDataWithContext(context,
				      get_auth_data_with_context_fn);

  smbc_setOptionUseKerberos(context, (_smb_flags & SMB_PROMPT_PASSWORD) ? 0 : 1);
  smbc_setOptionUseCCache(context, 1);
  smbc_setOptionFallbackAfterKerberos(context, 1);
  smbc_setOptionOneSharePerServer(context, 1);

  if (!smbc_init_context(context)) {
    smbc_free_context(context, 0);
    return -1;
  }

  /* Tell the compatibility layer to use this context */
  smbc_set_context(context);
  return 0;
}



static int
_smb_name_to_uid(const char *name,
		 uid_t *uidp) {
  struct passwd *pp;
  const char *dp;


  pp = getpwnam(name);
  if (!pp) {
    dp = strchr(name, '\\');
    if (dp) {
      /* XXX: Verify that WORKGROUP is "our" */
      name = dp+1;
      pp = getpwnam(name);
    }

    if (!pp) {
      char *cp, *nbuf;
      int fixflag = 0;
      
      nbuf = s_dup(name);
      if (!nbuf)
	return -1;
      
      for (cp = nbuf; *cp; cp++)
	if (isspace(*cp)) {
	  fixflag = 1;
	  *cp = '_';
	}
      
      if (fixflag)
	pp = getpwnam(nbuf);
      
      if (!pp) {
	for (cp = nbuf; *cp; cp++)
	  if (isupper(*cp))
	    *cp = tolower(*cp);
	
	pp = getpwnam(nbuf);
	if (!pp) {
	  free(nbuf);
	  return -1;
	}
      }
    }
  }
  
  *uidp = pp->pw_uid;
  return 0;
}


static int
_smb_name_to_gid(const char *name,
		 gid_t *gidp) {
  struct group *gp;
  const char *dp;

  
  gp = getgrnam(name);
  if (!gp) {
    dp = strchr(name, '\\');
    if (dp) {
      /* XXX: Verify that WORKGROUP is "our" */
      name = dp+1;
      gp = getgrnam(name);
    }
    if (!gp) {
      char *cp, *nbuf;
      int fixflag = 0;
      
      nbuf = s_dup(name);
      if (!nbuf)
	return -1;
      
      for (cp = nbuf; *cp; cp++)
	if (isspace(*cp)) {
	  fixflag = 1;
	  *cp = '_';
	}

      if (fixflag)
	gp = getgrnam(nbuf);
      
      if (!gp) {
	for (cp = nbuf; *cp; cp++)
	  if (isupper(*cp))
	    *cp = tolower(*cp);
	
	gp = getgrnam(nbuf);
	if (!gp) {
	  free(nbuf);
	  return -1;
	}
      }
    }
  }

  *gidp = gp->gr_gid;
  return 0;
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
  

  if (_smb_init() < 0)
    return -1;
  
  rc = smbc_stat(path, sp);
  if (rc < 0)
    return rc;

  /*
   * Hack to override the st_uid & st_gid with the real owner & group 
   */
  if (smb_getxattr(path, owner_attr, buf, sizeof(buf)) >= 0) {
    sp->st_uid = -1;
    _smb_name_to_uid(buf, &sp->st_uid);
  }
  
  if (smb_getxattr(path, group_attr, buf, sizeof(buf)) >= 0) {
    sp->st_gid = -1;
    _smb_name_to_gid(buf, &sp->st_gid);
  }

  return rc;
}


int
smb_statvfs(const char *path,
	    struct statvfs *sp) {
  int rc;
  
  if (_smb_init() < 0)
    return -1;

  memset(sp, 0, sizeof(*sp));
  rc = smbc_statvfs((char *) path, sp);

  /* 
   * HACK: Samba sets this to some silly small value sometimes
   */
  if (sp->f_frsize < 1024) {
    sp->f_frsize = 1024;
  }
  
  return rc;
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
  if (_smb_init() < 0)
    return -1;

  return smbc_getxattr(path, attr, buf, bufsize);
}

int
smb_setxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize) {
  if (_smb_init() < 0)
    return -1;
  
  return smbc_setxattr(path, attr, buf, bufsize, 0);
}

int
smb_removexattr(const char *path,
		const char *attr) {
  if (_smb_init() < 0)
    return -1;
  
  return smbc_removexattr(path, attr);
}


/*
 * The ACL attribute is formatted as a comma-separated 
 * list of ACE entries:
 *
 *  AD\peter86:0/11/0x001e01ff
 *  AD\employee-liu.se:0/3/0x00120088
 *  \Everyone:0/11/0x00120088
 *  AD\peter86:0/0/0x001e01ff
 *  AD\Domain_Users:0/0/0x001200a9
 *  \Everyone:0/0/0x001200a9
 */
#define SECATTR "system.nt_sec_desc.*+"
#define ACLATTR "system.nt_sec_desc.acl.*+"

static struct permtab {
  int s;
  GACL_PERM g;
} permtab[] =
  {
   { SMB_ACL_PERM_RD,   GACL_PERM_READ_DATA },
   { SMB_ACL_PERM_WD,   GACL_PERM_WRITE_DATA },
   { SMB_ACL_PERM_X,    GACL_PERM_EXECUTE },
   { SMB_ACL_PERM_AD,   GACL_PERM_APPEND_DATA },
   { SMB_ACL_PERM_REA,  GACL_PERM_READ_NAMED_ATTRS },
   { SMB_ACL_PERM_WEA,  GACL_PERM_WRITE_NAMED_ATTRS },
   { SMB_ACL_PERM_DC,   GACL_PERM_DELETE_CHILD },
   { SMB_ACL_PERM_D,    GACL_PERM_DELETE },
   { SMB_ACL_PERM_RA,   GACL_PERM_READ_ATTRIBUTES },
   { SMB_ACL_PERM_WA,   GACL_PERM_WRITE_ATTRIBUTES },
   { SMB_ACL_PERM_RC,   GACL_PERM_READ_ACL },
   { SMB_ACL_PERM_WDAC, GACL_PERM_WRITE_ACL },
   { SMB_ACL_PERM_WO,   GACL_PERM_WRITE_OWNER },
   { SMB_ACL_PERM_S,    GACL_PERM_SYNCHRONIZE },
  };

static struct flagtab {
  int s;
  GACL_FLAG g;
} flagtab[] =
  {
   { SMB_ACL_FLAG_OI, GACL_FLAG_FILE_INHERIT },
   { SMB_ACL_FLAG_CI, GACL_FLAG_DIRECTORY_INHERIT },
   { SMB_ACL_FLAG_NI, GACL_FLAG_NO_PROPAGATE_INHERIT },
   { SMB_ACL_FLAG_IO, GACL_FLAG_INHERIT_ONLY },
   { SMB_ACL_FLAG_I,  GACL_FLAG_INHERITED },
   
  };

#define SMB_TAG_TYPE_EVERYONE_TEXT "\\Everyone"

GACL *
smb_acl_get_file(const char *path) {
  char buf[32768], *bp, *cp;
  GACL *ap;
  int n_ace;
  int i, n;
  char *s_revision;
  char *s_owner;
  char *s_group;

  
  if (smb_getxattr(path, SECATTR, buf, sizeof(buf)) < 0)
    return NULL;
#if 0
  fprintf(stderr, "getxattr(\"%s\", \"%s\") -> '%s'\n",
	  path, SECATTR, buf);
#endif  
  n_ace = 1;
  for (bp = buf; *bp; bp++)
    if (*bp == ',')
      ++n_ace;
  
  ap = gacl_init(n_ace);
  if (!ap)
    return NULL;
		 
  bp = buf;

  s_revision = strsep(&bp, ",");
  
  if (strncmp(s_revision, "REVISION:", 9) != 0)
    goto Fail;
  s_revision += 9;
  
  s_owner = strsep(&bp, ",");
  if (strncmp(s_owner, "OWNER:", 6) != 0)
    goto Fail;
  s_owner += 6;
  
  s_group = strsep(&bp, ",");
  if (strncmp(s_group, "GROUP:", 6) != 0)
    goto Fail;
  s_group += 6;

  strncpy(ap->owner, s_owner, sizeof(ap->owner)-1);
  strncpy(ap->group, s_group, sizeof(ap->group)-1);

  while ((cp = strsep(&bp, ",")) != NULL) {
    char *s_tag;
    char *s_user;
    int type, flags, perms;
    GACL_ENTRY *ep = NULL;
    GACL_PERMSET ps;
    GACL_FLAGSET fs;
    GACL_TAG_TYPE e_type;
    uid_t e_ugid;
    char *e_name;

    
    s_tag = strsep(&cp, ":");
    if (strcmp(s_tag, "ACL") != 0)
      goto Fail;

    s_user = strsep(&cp, ":");
    if (!s_user)
      goto Fail;
    
    if (s_sepint(&type,  &cp, "/") < 1 ||
	s_sepint(&flags, &cp, "/") < 1 ||
	s_sepint(&perms, &cp, "/") < 1) {
      goto Fail;
    }
    
    e_type = -1;
    e_ugid = -1;

    if (strcmp(s_user, SMB_TAG_TYPE_EVERYONE_TEXT) == 0) {
      e_type = GACL_TAG_TYPE_EVERYONE;
      e_name = s_dup(GACL_TAG_TYPE_EVERYONE_TEXT);
    }
    else {
      e_name = s_dup(s_user);
      int rc_uid, rc_gid;
      uid_t uid = -1;
      gid_t gid = -1;
      
      rc_uid = _smb_name_to_uid(s_user, &uid);
      rc_gid = _smb_name_to_gid(s_user, &gid);
      
      if ((rc_uid < 0 && rc_gid < 0) ||
	  (rc_uid == 0 && rc_gid == 0)) {
	
	/* Name matches both user and group, or totally unknown */
	e_type = GACL_TAG_TYPE_UNKNOWN;
	if (uid == gid)
	  e_ugid = uid;
	else
	  e_ugid = -1;
	
      } else if (rc_uid == 0) {
	
	e_type = GACL_TAG_TYPE_USER;
	e_ugid = uid;
	
      } else {
	e_type = GACL_TAG_TYPE_GROUP;
	e_ugid = gid;
      }
    }
    
    if (gacl_create_entry(&ap, &ep) < 0)
      goto Fail;

    ep->tag.type = e_type;
    ep->tag.ugid = e_ugid;
    ep->tag.name = e_name;
    
    switch (type) {
    case SMB_ACL_TYPE_ALLOW:
      gacl_set_entry_type_np(ep, GACL_ENTRY_TYPE_ALLOW);
      break;
    case SMB_ACL_TYPE_DENY:
      gacl_set_entry_type_np(ep, GACL_ENTRY_TYPE_DENY);
      break;
    case SMB_ACL_TYPE_AUDIT:
      gacl_set_entry_type_np(ep, GACL_ENTRY_TYPE_AUDIT);
      break;
    case SMB_ACL_TYPE_ALARM:
      gacl_set_entry_type_np(ep, GACL_ENTRY_TYPE_ALARM);
      break;
    default:
      goto Fail;
    }

    gacl_clear_flags_np(&fs);
    n = sizeof(flagtab)/sizeof(flagtab[0]);
    for (i = 0; i < n; i++)
      if (flags & flagtab[i].s)
	gacl_add_flag_np(&fs, flagtab[i].g);
    gacl_set_flagset_np(ep, &fs);
    
    gacl_clear_perms(&ps);
    n = sizeof(permtab)/sizeof(permtab[0]);
    for (i = 0; i < n; i++)
      if (perms & permtab[i].s)
	gacl_add_perm(&ps, permtab[i].g);
    gacl_set_permset(ep, &ps);
  }

  return ap;
  
 Fail:
  gacl_free(ap);
  errno = EINVAL;
  return NULL;
}


static int
smb_gacl_entry_to_text(GACL_ENTRY *ep,
		       char *buf,
		       size_t bufsize,
		       char *owner,
		       char *group) {
  char *name;
  int type, i, n;
  int perms, flags;
  
  
  switch (ep->tag.type) {
  case GACL_TAG_TYPE_USER_OBJ:
    name = owner;
    break;
    
  case GACL_TAG_TYPE_GROUP_OBJ:
    name = group;
    break;
    
  case GACL_TAG_TYPE_USER:
  case GACL_TAG_TYPE_GROUP:
    name = ep->tag.name;
    break;
    
  case GACL_TAG_TYPE_EVERYONE:
    name = SMB_TAG_TYPE_EVERYONE_TEXT;
    break;

  default:
    errno = EINVAL;
    return -1;
  }

  switch (ep->type) {
  case GACL_ENTRY_TYPE_ALLOW:
    type = SMB_ACL_TYPE_ALLOW;
    break;
  case GACL_ENTRY_TYPE_DENY:
    type = SMB_ACL_TYPE_DENY;
    break;
  case GACL_ENTRY_TYPE_AUDIT:
    type = SMB_ACL_TYPE_AUDIT;
    break;
  case GACL_ENTRY_TYPE_ALARM:
    type = SMB_ACL_TYPE_ALARM;
    break;
  default:
    errno = EINVAL;
    return -1;
  }

  perms = 0;
  n = sizeof(permtab)/sizeof(permtab[0]);
  for (i = 0; i < n; i++) {
    if (ep->perms & permtab[i].g)
      perms |= permtab[i].s;
  }
  
  flags = 0;
  n = sizeof(flagtab)/sizeof(flagtab[0]);
  for (i = 0; i < n; i++) {
    if (ep->flags & flagtab[i].g)
      flags |= flagtab[i].s;
  }
  
  return snprintf(buf, bufsize, "ACL:%s:%u/%u/%u", /* 0x%08x */
		  name,
		  type,
		  flags,
		  perms);
}


int
smb_acl_set_file(const char *path,
		 GACL *ap) {
  SLIST *sp = NULL;
  char *abuf = NULL;
  int i;
  int need_owner = 0;
  int need_group = 0;

  
  sp = slist_new(ap->ac);
  if (!sp)
    return -1;

  slist_add(sp, "REVISION:1");

  /* Do we need to lookup the owner and/or group? */
  for (i = 0; i < ap->ac && !need_owner && !need_group; i++) {
    GACL_ENTRY *ep = &ap->av[i];
  
    if (ep->tag.type == GACL_TAG_TYPE_USER_OBJ && !ap->owner[0])
      need_owner = 1;
    
    if (ep->tag.type == GACL_TAG_TYPE_GROUP_OBJ && !ap->group[0])
      need_group = 1;
  }

  if (need_owner) {
    const char *owner_attr = "system.nt_sec_desc.owner+";
    char buf[256];
    
    if (smb_getxattr(path, owner_attr, buf, sizeof(buf)) < 0)
      return -1;

    strncpy(ap->owner, buf, sizeof(ap->owner));
  }

  if (need_group) {
    const char *group_attr = "system.nt_sec_desc.group+";
    char buf[256];
    
    if (smb_getxattr(path, group_attr, buf, sizeof(buf)) < 0)
      return -1;

    strncpy(ap->group, buf, sizeof(ap->group));
  }

#if 0 /* We can skip these (atleast for now) */
  if (ap->owner[0]) {
    char buf[512];
    
    snprintf(buf, sizeof(buf), "OWNER:%s", ap->owner);
    slist_add(sp, buf);
  }
  
  if (ap->group[0]) {
    char buf[512];
  
    snprintf(buf, sizeof(buf), "GROUP:%s", ap->group);
    slist_add(sp, buf);
  }
#endif
  
  for (i = 0; i < ap->ac; i++) {
    char ebuf[256];
    if (smb_gacl_entry_to_text(&ap->av[i], ebuf, sizeof(ebuf), ap->owner, ap->group) < 0)
      goto Fail;

    slist_add(sp, ebuf);
  }
  
  abuf = slist_join(sp, ",");
  if (!abuf)
    goto Fail;

#if 0
  fprintf(stderr, "setxattr(\"%s\", \"%s\")\n", SECATTR, abuf);
#endif
  
  if (smb_setxattr(path, SECATTR, abuf, strlen(abuf)) < 0)
    goto Fail;

  return 0;

 Fail:
  if (abuf)
    free(abuf);
  if (sp)
    slist_free(sp);
  return -1;
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

int
smb_acl_set_file(const char *path,
		 GACL *ap) {
  errno = ENOSYS;
  return -1;
}

#endif
