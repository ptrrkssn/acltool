/* linux.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <grp.h>

#include "gacl.h"
#include "nfs4.h"

#define ACL_NFS4_XATTR "system.nfs4_acl"

/*
 * xattr format:
 * 
 * struct acl {
 *   u_int32_t ace_c;
 *   struct ace {
 *     u_int32_t type;
 *     u_int32_t flags;
 *     u_int32_t perms;
 *     struct utf8str_mixed {
 *       u_int32_t len;
 *       char buf[len];
 *     } id;
 *   } ace_v[ace_c];
 * };
 */


static char *
_nfs4_id_domain(void) {
  static char *saved_domain = NULL;
  FILE *fp;
  char buf[256];


  if (saved_domain)
    return saved_domain;

  fp = fopen("/etc/idmapd.conf","r");
  if (!fp)
    return NULL;

  while (fgets(buf, sizeof(buf), fp)) {
    char *bp, *a, *b;
    bp = buf;
    a = strsep(&bp, " \t=");
    if (a && strcmp(a, "Domain") == 0) {
      b = strsep(&bp, " \t=");
      if (b)
	saved_domain = strdup(b);
      break;
    }
  }

  fclose(fp);
  return saved_domain;
}

/* This code is a bit of a hack */
static int
_nfs4_id_to_uid(char *buf,
		size_t bufsize,
		uid_t *uidp) {
  struct passwd *pp;
  int i;
  char *idd = NULL;
  int iddlen = -1;


  if (bufsize < 1)
    return -1;

  for (i = 0; i < bufsize && buf[i] != '@'; i++)
    ;

  if (i < bufsize) {
    buf[i++] = '\0';
    
    if (!idd || (iddlen == bufsize-i && strncmp(idd, buf+i, iddlen) == 0)) {
      pp = getpwnam(buf);
      if (pp) {
	*uidp = pp->pw_uid;
	return 1;
      }
    }
  } else if (sscanf(buf, "%d", uidp) == 1)
    return 1;

  return 0;
}

/* This code is a bit of a hack */
static int
_nfs4_id_to_gid(char *buf,
		size_t bufsize,
		gid_t *gidp) {
  struct group *gp;
  int i;
  char *idd = NULL;
  int iddlen = -1;


  if (bufsize < 1)
    return -1;

  idd = _nfs4_id_domain();
  if (idd)
    iddlen = strlen(idd);

  for (i = 0; i < bufsize && buf[i] != '@'; i++)
    ;

  if (i < bufsize) {
    buf[i++] = '\0';
    
    if (!idd || (iddlen == bufsize-i && strncmp(idd, buf+i, iddlen) == 0)) {
      gp = getgrnam(buf);
      if (gp) {
	*gidp = gp->gr_gid;
	return 1;
      }
    }
  } else if (sscanf(buf, "%d", gidp) == 1)
    return 1;

  return 0;
}


static GACL *
_gacl_init_from_nfs4(const char *buf,
		     size_t bufsize) {
  int i;
  u_int32_t *vp;
  u_int32_t na;
  char *cp;
  GACL *ap;

  
  vp = (u_int32_t *) buf;
  na = ntohl(*vp++);
  
  ap = gacl_init(na);
  if (!ap)
    return NULL;

  ap->type = GACL_TYPE_NFS4;
  
  for (i = 0; i < na; i++) {
    u_int32_t idlen;
    GACE *ep;
    
    if (gacl_create_entry_np(&ap, &ep, i) < 0) {
      gacl_free(ap);
      return NULL;
    }
    
    ep->type =  ntohl(*vp++);
    ep->flags = ntohl(*vp++);
    ep->perms = ntohl(*vp++);
    
    idlen = ntohl(*vp++);
    cp = (char *) vp;

    if (ep->flags & NFS4_ACE_IDENTIFIER_GROUP) {
      if (strncmp(cp, "GROUP@", idlen) == 0) {
	ep->tag = GACE_TAG_GROUP_OBJ;
	ep->id = -1;
      } else {
	ep->id = -1;
	(void) _nfs4_id_to_gid(cp, idlen, &ep->id);
	ep->tag = GACE_TAG_GROUP;
      }
    } else {
      if (strncmp(cp, "OWNER@", idlen) == 0) {
	ep->tag = GACE_TAG_USER_OBJ;
	ep->id = -1;
      } else if (strncmp(cp, "EVERYONE@", idlen) == 0) {
	ep->tag = GACE_TAG_EVERYONE;
	ep->id = -1;
      } else {
	ep->id = -1;
	(void) _nfs4_id_to_uid(cp, idlen, &ep->id);
	ep->tag = GACE_TAG_USER;
      }
    }

#if 0
    printf(" - T=%d, F=%08x, P=%08x, ID=%d (%.*s)\n", 
	   ep->type, ep->flags, ep->perms, ep->id, idlen, cp);
#endif

    vp += idlen / sizeof(u_int32_t);
    if (idlen % sizeof(u_int32_t))
      vp++;
  }

  return ap;
}


GACL *
_gacl_get_fd_file(int fd,
		  const char *path,
		  GACL_TYPE type,
		  int flags) {
  char *buf;
  ssize_t bufsize, rc;

  
  if (path) {
    if (flags & GACL_F_SYMLINK_NOFOLLOW) {
    
      bufsize = lgetxattr(path, ACL_NFS4_XATTR, NULL, 0);
      if (bufsize < 0)
	return NULL;

      buf = malloc(bufsize);
      if (!buf)
	return NULL;

      rc = lgetxattr(path, ACL_NFS4_XATTR, buf, bufsize);
      if (rc < 0) {
	free(buf);
	return NULL;
      }
    } else {
      
      bufsize = getxattr(path, ACL_NFS4_XATTR, NULL, 0);
      if (bufsize < 0)
	return NULL;
      
      buf = malloc(bufsize);
      if (!buf)
	return NULL;
      
      rc = getxattr(path, ACL_NFS4_XATTR, buf, bufsize);
      if (rc < 0) {
	free(buf);
	return NULL;
      }
      
    }
  } else {
    
    bufsize = fgetxattr(fd, ACL_NFS4_XATTR, NULL, 0);
    if (bufsize < 0)
      return NULL;
    
    buf = malloc(bufsize);
    if (!buf)
      return NULL;
    
    rc = fgetxattr(fd, ACL_NFS4_XATTR, buf, bufsize);
    if (rc < 0) {
      free(buf);
      return NULL;
    }
    
  }

  return _gacl_init_from_nfs4(buf, bufsize);
}



static ssize_t 
_gacl_to_nfs4(GACL *ap, 
	      char *buf, 
	      size_t bufsize) {
  u_int32_t *vp, *endp;
  size_t buflen, vlen;
  int i, rc;


  vp = (u_int32_t *) buf;
  buflen = bufsize/sizeof(u_int32_t);
  endp = vp+buflen;

  /* Number of ACEs */
  *vp++ = htonl(ap->ac);

  for (i = 0; i < ap->ac; i++) {
    char *idname;
    u_int32_t idlen;
    struct passwd *pp;
    struct group *gp;
    char *idd;
    char tbuf[256];
    GACE *ep = &ap->av[i];

    if (vp >= endp) {
      errno = ENOMEM;
      return -1;
    }
    *vp++ = htonl(ep->type);

    if (vp >= endp) {
      errno = ENOMEM;
      return -1;
    }
    *vp++ = htonl(ep->flags | (ep->tag == GACE_TAG_GROUP || ep->tag == GACE_TAG_GROUP_OBJ ? 
			       NFS4_ACE_IDENTIFIER_GROUP : 0));
    
    if (vp >= endp) {
      errno = ENOMEM;
      return -1;
    }
    *vp++ = htonl(ep->perms);

    switch (ep->tag) {
    case GACE_TAG_USER_OBJ:
      idname = "OWNER@";
      break;
    case GACE_TAG_GROUP_OBJ:
      idname = "GROUP@";
      break;
    case GACE_TAG_EVERYONE:
      idname = "EVERYONE@";
      break;
    case GACE_TAG_USER:
      pp = getpwuid(ep->id);
      if (pp) {
	idd = _nfs4_id_domain();
	rc = snprintf(tbuf, sizeof(tbuf), "%s@%s", pp->pw_name, idd ? idd : "");
      } else
	rc = snprintf(tbuf, sizeof(tbuf), "%u", ep->id);
      if (rc < 0) {
	errno = EINVAL;
	return -1;
      }
      idname = tbuf;
      break;
    case GACE_TAG_GROUP:
      gp = getgrgid(ep->id);
      if (gp) {
	idd = _nfs4_id_domain();
	rc = snprintf(tbuf, sizeof(tbuf), "%s@%s", gp->gr_name, idd ? idd : "");
      } else
	rc = snprintf(tbuf, sizeof(tbuf), "%u", ep->id);
      if (rc < 0) {
	errno = EINVAL;
	return -1;
      }
      idname = tbuf;
      break;
    default:
      errno = EINVAL;
      return -1;
    }

    idlen = strlen(idname);
    vlen = idlen / sizeof(u_int32_t);
    if (idlen % sizeof(u_int32_t))
      ++vlen;

    if (vp+vlen >= endp) {
      errno = ENOMEM;
      return -1;
    }
    *vp++ = htonl(idlen);
    memcpy(vp, idname, idlen);
    vp += vlen;
  }

  return ((char *) vp) - buf;
}


int
_gacl_set_fd_file(int fd,
		  const char *path,
		  GACL_TYPE type,
		  GACL *ap,
		  int flags) {
  char buf[8192];
  ssize_t bufsize, rc;


  bufsize = _gacl_to_nfs4(ap, buf, sizeof(buf));
  if (bufsize < 0)
    return -1;

  if (path) {
    if (flags & GACL_F_SYMLINK_NOFOLLOW) {
    
      rc = lsetxattr(path, ACL_NFS4_XATTR, buf, bufsize, 0);
      if (rc < 0)
	return -1;

    } else {
      
      rc = setxattr(path, ACL_NFS4_XATTR, buf, bufsize, 0);
      if (rc < 0)
	return -1;
      
    }
  } else {
    
    rc = fsetxattr(fd, ACL_NFS4_XATTR, buf, bufsize, 0);
    if (rc < 0)
      return -1;
    
  }

  return rc;
}
