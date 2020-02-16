/*
 * gacl.c - Generic ACLs - Emulate FreeBSD acl* functionality
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "gacl.h"


/* Internal: Convert to and from Solaris ace_t to standard GACE entry */
static int
_gacl_entry_to_ace(GACE *ep,
		   ace_t *ap) {
  if (!ep || !ap) {
    errno = EINVAL;
    return -1;
  }

  switch (ep->tag) {
  case GACE_TAG_USER_OBJ:
    ap->a_flags = ACE_OWNER;
    break;

  case GACE_TAG_GROUP_OBJ:
    ap->a_flags = (ACE_GROUP|ACE_IDENTIFIER_GROUP);
    break;

  case GACE_TAG_EVERYONE:
    ap->a_flags = ACE_EVERYONE;
    break;

  case GACE_TAG_USER:
    break;

  case GACE_TAG_GROUP:
    ap->a_flags = ACE_IDENTIFIER_GROUP;
    break;

  default:
    errno = ENOSYS;
    return -1;
  }
  
  ap->a_who = ep->id;
  ap->a_access_mask = ep->perms;
  ap->a_flags |= ep->flags;
  ap->a_type  = ep->type;
  
  return 0;
}

static int
_gacl_entry_from_ace(GACE *ep,
		     ace_t *ap) {
  if (!ep || !ap) {
    errno = EINVAL;
    return -1;
  }

  switch (ap->a_flags & (ACE_OWNER|ACE_GROUP|ACE_EVERYONE)) {
  case ACE_OWNER:
    ep->tag = GACE_TAG_USER_OBJ;
    break;

  case ACE_GROUP:
    ep->tag = GACE_TAG_GROUP_OBJ;
    break;

  case ACE_EVERYONE:
    ep->tag = GACE_TAG_EVERYONE;
    break;

  default:
    if (ap->a_flags & ACE_IDENTIFIER_GROUP)
      ep->tag = GACE_TAG_GROUP;
    else
      ep->tag = GACE_TAG_USER;
  }
  
  ep->id    = ap->a_who;
  ep->perms = ap->a_access_mask;
  ep->flags = (ap->a_flags & GACE_FLAGS_ALL);
  ep->type  = ap->a_type;
  
  return 0;
}



GACL *
_gacl_get_fd_file(int fd,
		  const char *path,
		  GACL_TYPE type,
		  int flags) {
  GACL *ap;
  int i, n;
#if 0
  aclent_t *aep;
#endif
  ace_t *acp;

  
  if (path && (flags & GACL_F_SYMLINK_NOFOLLOW)) {
    struct stat sb;
    
    if (lstat(path, &sb) < 0)
      return NULL;
    
    if (S_ISLNK(sb.st_mode)) {
      /* Solaris doesn't support doing ACL operations on symbolic links - sorry */
      errno = ENOSYS;
      return NULL;
    }
  }
  
  switch (type) {
  case GACL_TYPE_NONE:
    return gacl_init(0);

  case GACL_TYPE_NFS4:
    if (path)
      n = acl(path, ACE_GETACLCNT, 0, NULL);
    else
      n = facl(fd, ACE_GETACLCNT, 0, NULL);
      
    if (n < 0)
      return NULL;

    acp = calloc(n, sizeof(*acp));
    if (!acp) {
      return NULL;
    }
    
    ap = gacl_init(n);
    if (!ap) {
      free(acp);
      return NULL;
    }

    ap->type = type;
    ap->ac = n;
    
    if (path)
      n = acl(path, ACE_GETACL, n, (void *) acp);
    else
      n = facl(fd, ACE_GETACL, n, (void *) acp);
    if (n < 0) {
      free(acp);
      gacl_free(ap);
      return NULL;
    }
    
    for (i = 0; i < n; i++)
      if (_gacl_entry_from_ace(&ap->av[i], &acp[i]) < 0) {
	free(acp);
	gacl_free(ap);
	return NULL;
      }
    return ap;

#if 0
  case GACL_TYPE_ACCESS:
  case GACL_TYPE_DEFAULT:
    if (path)
      n = acl(path, GETACLCNT, 0, NULL);
    else
      n = facl(fd, GETACLCNT, 0, NULL);
    if (n < 0)
      return NULL;

    aep = calloc(n, sizeof(*aep));
    if (!aep)
      return NULL;
    
    ap = gacl_init(n);
    if (!ap) {
      free(aep);
      return NULL;
    }

    ap->type = type;
    ap->ac = n;
    
    if (path)
      n = acl(path, GETACL, n, (void *) aep);
    else
      n = facl(fd, GETACL, n, (void *) aep);
    if (n < 0) {
      gacl_free(ap);
      return NULL;
    }
    for (i = 0; i < n; i++)
      if (_gacl_entry_from_aclent(&ap->av[i], &aep[i]) < 0) {
	free(acp);
	gacl_free(ap);
	return NULL;
      }
    ap->type = type;
    ap->ac = cnt;
    return ap;
#endif
    
  default:
    errno = ENOSYS;
    return NULL;
  }

  errno = EINVAL;
  return NULL;
}



int
_gacl_set_fd_file(int fd,
		  const char *path,
		  GACL_TYPE type,
		  GACL *ap,
		  int flags) {
  int i, rc;
  ace_t *acp;
#if 0
  aclent_t *aep;
#endif
  
  if (path && (flags & GACL_F_SYMLINK_NOFOLLOW)) {
    struct stat sb;
    
    if (lstat(path, &sb) < 0)
      return -1;
    
    if (S_ISLNK(sb.st_mode)) {
      /* Solaris doesn't support doing ACL operations on symbolic links - sorry */
      errno = ENOSYS;
      return -1;
    }
  }
  
  switch (type) {
  case GACL_TYPE_NONE:
    /* XXX: Remove ACL? */
    errno = ENOSYS;
    return -1;
    
  case GACL_TYPE_NFS4:
    acp = calloc(ap->ac, sizeof(*acp));
    if (!acp)
      return -1;

    for (i = 0; i < ap->ac; i++)
      if (_gacl_entry_to_ace(&ap->av[i], &acp[i]) < 0) {
	free(acp);
	return -1;
      }
    
    if (path)
      rc = acl(path, ACE_SETACL, ap->ac, (void *) acp);
    else
      rc = facl(fd, ACE_SETACL, ap->ac, (void *) acp);
    free(acp);
    fprintf(stderr, "rc=%d\n", rc);
    return rc;

#if 0
  case GACL_TYPE_ACCESS:
    /* XXX: Do special handling? (R-M-W - only update access parts) */
    if (acl(path, SETACL, ap->ac, (void *) &ap->av[0]) < 0)
      return -1;
    return 0;
    
  case GACL_TYPE_DEFAULT:
    /* XXX: Do special handling? (R-M-W - only update default parts) */
    if (acl(path, SETACL, ap->ac, (void *) &ap->av[0]) < 0)
      return -1;
    return 0;
#endif

  default:
    errno = EINVAL;
    return -1;
  }
}





