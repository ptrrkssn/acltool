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


static struct gace_perm2c {
  int p;
  char c;
  char *s;
} gace_p2c[] = {
		{ GACE_READ_DATA, 'r', "read_data" },
		{ GACE_WRITE_DATA, 'w', "write_data" },
		{ GACE_EXECUTE, 'x', "execute" },
		{ GACE_APPEND_DATA, 'p', "append_data" },
		{ GACE_DELETE, 'd', "delete" },
		{ GACE_DELETE_CHILD, 'D', "delete_child" },
		{ GACE_READ_ATTRIBUTES, 'a', "read_attributes" },
		{ GACE_WRITE_ATTRIBUTES, 'A', "write_attributes" },
		{ GACE_READ_NAMED_ATTRS, 'R', "read_xattrs" },
		{ GACE_WRITE_NAMED_ATTRS, 'W', "write_xattrs" },
		{ GACE_READ_ACL, 'c', "read_acl" },
		{ GACE_WRITE_ACL, 'C', "write_acl" },
		{ GACE_WRITE_OWNER, 'o', "write_owner" },
		{ GACE_SYNCHRONIZE, 's', "synchronize" },
		{ 0, 0 }
};

static struct gace_flag2c {
  int f;
  char c;
} gace_f2c[] = {
		{ GACE_FLAG_FILE_INHERIT, 'f' },
		{ GACE_FLAG_DIRECTORY_INHERIT, 'd' },
		{ GACE_FLAG_INHERIT_ONLY, 'i' },
		{ GACE_FLAG_NO_PROPAGATE_INHERIT, 'n' },
		{ GACE_FLAG_SUCCESSFUL_ACCESS, 'S' },
		{ GACE_FLAG_FAILED_ACCESS, 'F' },
#ifdef GACE_FLAG_INHERITED
		{ GACE_FLAG_INHERITED, 'I' },
#endif
		{ 0, 0 }
};


GACL *
gacl_init(int count) {
  GACL *ap;
  size_t s;

  if (count < GACL_MAX_ENTRIES)
    count = GACL_MAX_ENTRIES;
  
  s = sizeof(*ap) + count*sizeof(ap->av[0]);
  ap = malloc(s);
  if (!ap)
    return NULL;

  ap->type = 0;
  ap->ac = 0;
  ap->ap = 0;
  ap->as = count;

  return ap;
}


int
gacl_free(void *op) {
  free(op);
  return 0;
}


int
gacl_init_entry(GACE *ep) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }
    
  memset(ep, 0, sizeof(*ep));
  return 0;
}

int
gacl_copy_entry(GACE *dep,
		GACE *sep) {
  if (!dep || !sep || dep == sep) {
    errno = EINVAL;
    return -1;
  }
  
  *dep = *sep;
  return 0;
}

int
gacl_get_entry(GACL *ap,
	       int eid,
	       GACE **epp) {
  if (!ap || !(eid == GACL_FIRST_ENTRY || eid == GACL_NEXT_ENTRY)) {
    errno = EINVAL;
    return -1;
  }

  if (eid == GACL_FIRST_ENTRY)
    ap->ap = 0;

  if (ap->ap >= ap->ac) {
    return 0;
  }

  *epp = &ap->av[ap->ap++];
  return 1;
}

/* If index < 0 or index > last -> append */
/* TODO: Realloc() GACL if need to extent to make room for more GACEs */
int
gacl_create_entry_np(GACL **app,
		     GACE **epp,
		     int index) {
  int i;
  GACL *ap;


  if (!app || !*app || !epp) {
    errno = EINVAL;
    return -1;
  }
  
  ap = *app;
  if (ap->ac >= ap->as) {
    errno = ENOMEM;
    return -1;
  }

  if (index < 0 || index > ap->ac)
      index = ap->ac;

  /* Make room */
  for (i = ap->ac; i > index; i--)
    gacl_copy_entry(&ap->av[i], &ap->av[i-1]);
  
  gacl_init_entry(&ap->av[index]);
  *epp = &ap->av[index];

  ap->ac++;
  return 0;
}

int
gacl_create_entry(GACL **app,
		  GACE **epp) {
  /* TODO: prepend or append ACEs? We prepend for now... */
  return gacl_create_entry_np(app, epp, 0);
}


int
gacl_add_entry_np(GACL **app,
		  GACE *ep,
		  int index) {
  GACE *nep;
  
  if (gacl_create_entry_np(app, &nep, index) < 0)
    return -1;

  if (gacl_copy_entry(nep, ep) < 0)
    return -1;

  return 0;
}

int
gacl_delete_entry_np(GACL *ap,
		     int index) {
  if (!ap || index < 0 || index >= ap->ac) {
    errno = EINVAL;
    return -1;
  }
  
  for (; index < ap->ac-1; index++)
    gacl_copy_entry(&ap->av[index], &ap->av[index+1]);
  ap->ac--;

  return 0;
}

int
gacl_delete_entry(GACL *ap,
		  GACE *ep) {
  int i;

  
  if (!ap || !ep) {
    errno = EINVAL;
    return -1;
  }

  for (i = 0; i < ap->ac && ep != &ap->av[i]; i++)
    ;

  if (i >= ap->ac) {
    errno = EINVAL;
    return -1;
  }
    
  return gacl_delete_entry_np(ap, i);
}


int
gacl_get_brand_np(GACL *ap,
		  GACL_BRAND *bp) {
  switch (ap->type) {
  case GACL_TYPE_NONE:
    *bp = GACL_BRAND_NONE;
    return 0;
    
  case GACL_TYPE_ACCESS:
  case GACL_TYPE_DEFAULT:
    *bp = GACL_BRAND_POSIX;
    return 0;
    
  case GACL_TYPE_NFS4:
    *bp = GACL_BRAND_NFS4;
    return 0;
  }

  errno = EINVAL;
  return -1;
}


GACL *
gacl_dup(GACL *ap) {
  GACL *nap;
  int i;

  
  nap = gacl_init(ap->as);
  if (!nap)
    return NULL;

  nap->type = ap->type;
  nap->ac = ap->ac;
  nap->ap = 0;
  for (i = 0; i < ap->ac; i++)
    if (gacl_copy_entry(&nap->av[i], &ap->av[i]) < 0) {
      gacl_free(nap);
      return NULL;
    }

  return nap;
}


int
gacl_is_trivial_np(GACL *ap,
		   int *trivialp) {
  GACE *ep;
  GACE_TAG t;
  int i, rc, tf;

  
  if (!ap || !trivialp) {
    errno = EINVAL;
    return -1;
  }
  
  tf = 1;
  for (i = 0; (rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1; i++) {
    if (gacl_get_tag_type(ep, &t) < 0)
      return -1;

    switch (ap->type) {
    case GACL_TYPE_NFS4:
      switch (t) {
      case GACE_TAG_USER_OBJ:
      case GACE_TAG_GROUP_OBJ:
      case GACE_TAG_EVERYONE:
	break;
	
      default:
	tf = 0;
      }
      break;

    default:
      errno = ENOSYS;
      return -1;
    }
  }
  
  *trivialp = tf;
  return 0;
}

/* TODO: Handle recalculate_mask */
GACL *
gacl_strip_np(GACL *ap,
	      int recalculate_mask) {
  GACL *nap;
  GACE *ep;
  GACE_TAG t;
  int i, rc;
  
  
  nap = gacl_init(ap->as);
  if (!nap)
    return NULL;
  
  for (i = 0; (rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1; i++) {
    if (gacl_get_tag_type(ep, &t) < 0)
      return NULL;

    switch (t) {
    case GACE_TAG_USER_OBJ:
    case GACE_TAG_GROUP_OBJ:
    case GACE_TAG_EVERYONE:
      gacl_add_entry_np(&nap, ep, -1);
      break;
    default:
      break;
    }

  }

  return nap;
}


int
gacl_equal(GACL *ap,
	   GACL *bp) {
  GACE *aep, *bep;
  GACE_TAG att, btt;
  GACE_PERMSET *apsp, *bpsp;
  GACE_FLAGSET *afsp, *bfsp;
  GACE_TYPE aet, bet;
  int p, arc, brc;
  

  if (ap->ac != bp->ac)
    return 0;

  if (ap->type != bp->type)
    return 0;
  
  p = GACL_FIRST_ENTRY;
  while ((arc = gacl_get_entry(ap, p, &aep)) == 1 && (brc = gacl_get_entry(bp, p, &bep)) == 1) {
    p = GACL_NEXT_ENTRY;

    switch (ap->type) {
    case GACL_TYPE_NFS4:
      if (gacl_get_tag_type(aep, &att) < 0)
	return -1;
      
      if (gacl_get_tag_type(bep, &btt) < 0)
	return -1;
      
      if (att != btt)
	return 0;
      
      if (gacl_get_permset(aep, &apsp) < 0)
	return -1;
      
      if (gacl_get_permset(bep, &bpsp) < 0)
	return -1;
      
      if (memcmp(apsp, bpsp, sizeof(*apsp)) != 0)
	return 0;
      
      if (gacl_get_flagset_np(aep, &afsp) < 0)
	return -1;
      
      if (gacl_get_flagset_np(bep, &bfsp) < 0)
	return -1;
      
      if (memcmp(afsp, bfsp, sizeof(*afsp)) != 0)
	return 0;
      
      if (gacl_get_entry_type_np(aep, &aet) < 0)
	return -1;
      
      if (gacl_get_entry_type_np(bep, &bet) < 0)
	return -1;
      
      if (aet != bet)
	return 0;
      break;

    case GACL_TYPE_ACCESS:
    case GACL_TYPE_DEFAULT:
      /* Not yet implemented */
    default:
      errno = ENOSYS;
      return -1;
    }
  }

  return 1;
}



GACL *
gacl_get_file(const char *path,
	      GACL_TYPE type) {
  return _gacl_get_fd_file(-1, path, type, 0);
}


GACL *
gacl_get_link_np(const char *path,
		 GACL_TYPE type) {
  return _gacl_get_fd_file(-1, path, type, GACL_F_SYMLINK_NOFOLLOW);
}


GACL *
gacl_get_fd_np(int fd,
	       GACL_TYPE type) {
  return _gacl_get_fd_file(fd, NULL, type, 0);
}

GACL *
gacl_get_fd(int fd) {
  return gacl_get_fd_np(fd, GACL_TYPE_ACCESS);
}


int
gacl_set_file(const char *path,
	      GACL_TYPE type,
	      GACL *ap) {
  return _gacl_set_fd_file(-1, path, type, ap, 0);
}


int
gacl_set_link_np(const char *path,
		 GACL_TYPE type,
		 GACL *ap) {
  return _gacl_set_fd_file(-1, path, type, ap, GACL_F_SYMLINK_NOFOLLOW);
}


int
gacl_set_fd_np(int fd,
	       GACL *ap,
	       GACL_TYPE type) {
  return _gacl_set_fd_file(fd, NULL, type, ap, 0);
}

int
gacl_set_fd(int fd,
	    GACL *ap) {
  return gacl_set_fd_np(fd, ap, GACL_TYPE_ACCESS);
}


int
gacl_get_tag_type(GACE *ep,
		  GACE_TAG *etp) {
  if (!ep || !etp) {
    errno = EINVAL;
    return -1;
  }

  *etp = ep->tag;
  return 0;
}

void *
gacl_get_qualifier(GACE *ep) {
  uid_t *idp;


  if (!ep) {
    errno = EINVAL;
    return NULL;
  }

  switch (ep->tag) {
  case GACE_TAG_USER:
  case GACE_TAG_GROUP:
    idp = malloc(sizeof(*idp));
    if (!idp)
      return NULL;

    *idp = ep->id;
    return (void *) idp;

  default:
    errno = EINVAL;
    return NULL;
  }
}

int
gacl_set_qualifier(GACE *ep,
		   const void *qp) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }

  switch (ep->tag) {
  case GACE_TAG_USER:
  case GACE_TAG_GROUP:
    ep->id = * (uid_t *) qp;
    return 0;

  default:
    errno = EINVAL;
    return -1;
  }
}


int
gacl_get_permset(GACE *ep,
		 GACE_PERMSET **pspp) {
  if (!ep || !pspp) {
    errno = EINVAL;
    return -1;
  }

  *pspp = &ep->perms;
  return 0;
}


int
gacl_set_permset(GACE *ep,
		 GACE_PERMSET *psp) {
  if (!ep || !psp) {
    errno = EINVAL;
    return -1;
  }

  ep->perms = *psp;
  return 0;
}


int
gacl_get_perm_np(GACE_PERMSET *epp,
		 GACE_PERM p) {
  if (!epp) {
    errno = EINVAL;
    return -1;
  }

  return (*epp & p) ? 1 : 0;
}

int
gacl_clear_perms(GACE_PERMSET *psp) {
  if (!psp) {
    errno = EINVAL;
    return -1;
  }
  
  *psp = 0;
  return 0;
}


int
gacl_add_perm(GACE_PERMSET *psp,
	      GACE_PERM p) {
  if (!psp) {
    errno = EINVAL;
    return -1;
  }

  *psp |= p;
  return 0;
}

int
gacl_delete_perm(GACE_PERMSET *psp,
		 GACE_PERM p) {
  if (!psp) {
    errno = EINVAL;
    return -1;
  }

  *psp &= ~p;
  return 0;
}


int
gacl_get_flagset_np(GACE *ep,
		    GACE_FLAGSET **fspp) {
  if (!ep || !fspp) {
    errno = EINVAL;
    return -1;
  }

  *fspp = &ep->flags;
  return 0;
}

int
gacl_set_flagset_np(GACE *ep,
		    GACE_FLAGSET *fsp) {
  if (!ep || !fsp) {
    errno = EINVAL;
    return -1;
  }

  ep->flags = *fsp;
  return 0;
}

int
gacl_clear_flags_np(GACE_FLAGSET *fsp) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }
  
  *fsp = 0;
  return 0;
}

int
gacl_get_flag_np(GACE_FLAGSET *fsp,
		 GACE_FLAG f) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }

  return (*fsp & f) ? 1 : 0;
}

int
gacl_add_flag_np(GACE_FLAGSET *fsp,
		 GACE_FLAG f) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }

  *fsp |= f;
  return 0;
}

int
gacl_delete_flag_np(GACE_FLAGSET *fsp,
		    GACE_FLAG f) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }

  *fsp &= ~f;
  return 0;
}


int
gacl_get_entry_type_np(GACE *ep,
		       GACE_TYPE *etp) {
  if (!ep || !etp) {
    errno = EINVAL;
    return -1;
  }

  *etp = ep->type;
  return 0;
}


int
gacl_set_entry_type_np(GACE *ep,
		       GACE_TYPE et) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }

  ep->type = et;
  return 0;
}



ssize_t
gacl_entry_tag_to_text(GACE *ep,
		       char *buf,
		       size_t bufsize,
		       int flags) {
  GACE_TAG et;
  struct passwd *pp;
  struct group *gp;

  
  if (gacl_get_tag_type(ep, &et) < 0)
    return -1;
  
  switch (et) {
  case GACE_TAG_UNDEFINED:
  case GACE_TAG_MASK:
  case GACE_TAG_OTHER_OBJ:
    return -1;
    
  case GACE_TAG_USER_OBJ:
    return snprintf(buf, bufsize, "owner@");
    
  case GACE_TAG_USER:
    pp = (flags & GACL_TEXT_NUMERIC_IDS) ? NULL : getpwuid(ep->id);
    if (pp)
      return snprintf(buf, bufsize, "user:%s", pp->pw_name);
    return snprintf(buf, bufsize, "user:%d", ep->id);
    
  case GACE_TAG_GROUP_OBJ:
    return snprintf(buf, bufsize, "group@");
    
  case GACE_TAG_GROUP:
    gp = (flags & GACL_TEXT_NUMERIC_IDS) ? NULL : getgrgid(ep->id);
    if (gp)
      return snprintf(buf, bufsize, "group:%s", gp->gr_name);
    return snprintf(buf, bufsize, "group:%d", ep->id);
    
  case GACE_TAG_EVERYONE:
    return snprintf(buf, bufsize, "everyone@");

  }

  errno = EINVAL;
  return -1;
}


ssize_t
gacl_entry_permset_to_text(GACE *ep,
			   char *buf,
			   size_t bufsize,
			   int flags) {
  GACE_PERMSET *epsp;
  GACE_PERM p;
  int a;

  
  if (gacl_get_permset(ep, &epsp) < 0)
    return -1;
  
  for (p = 0; bufsize > 1 && gace_p2c[p].c; p++) {
    a = gacl_get_perm_np(epsp, gace_p2c[p].p);
    if (a < 0)
      return -1;
    *buf++ = (a ? gace_p2c[p].c : '-');
    bufsize--;
  }

  return p;
}


ssize_t
gacl_entry_flagset_to_text(GACE *ep,
			   char *buf,
			   size_t bufsize,
			   int flags) {
  GACE_FLAGSET *efsp;
  GACE_FLAG f;
  int a;

  
  if (gacl_get_flagset_np(ep, &efsp) < 0)
    return -1;
  
  for (f = 0; bufsize > 1 && gace_f2c[f].c; f++) {
    a = gacl_get_flag_np(efsp, gace_f2c[f].f);
    if (a < 0)
      return -1;
    *buf++ = (a ? gace_f2c[f].c : '-');
    bufsize--;
  }

  return f;
}


ssize_t
gacl_entry_type_to_text(GACE *ep,
			char *buf,
			size_t bufsize,
			int flags) {
  GACE_TYPE et;

  
  if (gacl_get_entry_type_np(ep, &et) < 0)
    return -1;
  
  switch (et) {
  case GACE_TYPE_ALLOW:
    return snprintf(buf, bufsize, "allow");
  case GACE_TYPE_DENY:
    return snprintf(buf, bufsize, "deny");
  case GACE_TYPE_ALARM:
    return snprintf(buf, bufsize, "alarm");
  case GACE_TYPE_AUDIT:
    return snprintf(buf, bufsize, "audit");
  }

  errno = EINVAL;
  return -1;
}



ssize_t
gacl_entry_to_text(GACE *ep,
		   char *buf,
		   size_t bufsize,
		   int flags) {
  char *bp;
  ssize_t rc;
  
  
  bp = buf;
  
  rc = gacl_entry_tag_to_text(ep, bp, bufsize, flags);
  if (rc < 0)
    return -1;  
  bp += rc;
  bufsize -= rc;

  if (bufsize <= 1)
    return -1;
  *bp++ = ':';
  bufsize--;

  rc = gacl_entry_permset_to_text(ep, bp, bufsize, flags);
  if (rc < 0)
    return -1;
  bp += rc;
  bufsize -= rc;

  if (bufsize <= 1)
    return -1;
  *bp++ = ':';
  bufsize--;

  rc = gacl_entry_flagset_to_text(ep, bp, bufsize, flags);
  if (rc < 0)
    return -1;  
  bp += rc;
  bufsize -= rc;
  
  if (bufsize <= 1)
    return -1;
  *bp++ = ':';
  bufsize--;
  
  rc = gacl_entry_type_to_text(ep, bp, bufsize, flags);
  if (rc < 0)
    return -1;
  
  bp += rc;
  bufsize -= rc;
  
  if (flags & GACL_TEXT_APPEND_ID) {
    GACE_TAG et;
    
    if (gacl_get_tag_type(ep, &et) < 0)
      return -1;

    rc = 0;
    switch (et) {
    case GACE_TAG_USER:
      rc = snprintf(bp, bufsize, "\t# uid=%d", ep->id);
      break;
    case GACE_TAG_GROUP:
      rc = snprintf(bp, bufsize, "\t# gid=%d", ep->id);
      break;
    default:
      break;
    }
    if (rc < 0)
      return -1;
    bp += rc;
    bufsize -= rc;
  }
  
  return bp-buf;
}


char *
gacl_to_text_np(GACL *ap,
		ssize_t *bsp,
		int flags) {
  char *buf, *bp;
  size_t bufsize = 1024;
  int i, rc;
  GACE *ep;

  
  bp = buf = malloc(bufsize);
  if (!buf)
    return NULL;

  for (i = 0; bufsize > 1 && ((rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1); i++) {
    char es[80], *cp;
    ssize_t rc, len;
    
    rc = gacl_entry_to_text(ep, es, sizeof(es), flags);
    if (rc < 0)
      goto Fail;

    cp = strchr(es, ':');
    if (cp) {
      len = cp-es;
      if (len > 0 && (strncmp(es, "user", len) == 0 ||
		      strncmp(es, "group", len) == 0)) {
	cp = strchr(cp+1, ':');
	if (cp)
	  len = cp-es;
      }
    } else
      len = 0;
    
    rc = snprintf(bp, bufsize, " %*s%s\n", (int) (22-len), "", es);
    if (rc < 0)
      goto Fail;

    bp += rc;
    bufsize -= rc;
  }

  if (bsp)
    *bsp = (bp-buf);
  
  return buf;

 Fail:
  free(buf);
  return NULL;
}


char *
gacl_to_text(GACL *ap,
	     ssize_t *bsp) {
  return gacl_to_text_np(ap, bsp, 0);
}



#if 0
/* TODO: To be implemented */

gacl_valid() {
}

gacl_valid_fd_np() {
}

gacl_valid_file_np() {
}

gacl_valid_link_np() {
}

gacl_calc_mask() {
}


gacl_from_text() {
}

gacl_delete_fd_np() {
}

gacl_delete_file_np() {
}

gacl_delete_link_np() {
}

gacl_delete_def_file() {
}

gacl_delete_def_link_np() {
}

#endif


