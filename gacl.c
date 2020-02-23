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



/* Generate an ACL from Unix mode bits */
GACL *
_gacl_from_mode(mode_t mode) {
  GACL *ap;
  GACE *ep;
  GACE_PERM ua, ga, ea;


  ua = ga = ea = GACE_READ_ACL | GACE_READ_ATTRIBUTES | GACE_READ_NAMED_ATTRS | GACE_SYNCHRONIZE;
  ua |= GACE_WRITE_ACL | GACE_WRITE_OWNER | GACE_WRITE_ATTRIBUTES | GACE_WRITE_NAMED_ATTRS;

  if (mode & S_IRUSR)
    ua |= GACE_READ_DATA;
  if (mode & S_IWUSR)
    ua |= GACE_WRITE_DATA | GACE_APPEND_DATA;
  if (mode & S_IXUSR)
    ua |= GACE_EXECUTE;

  if (mode & S_IRGRP) 
    ga |= GACE_READ_DATA;
  if (mode & S_IWGRP)
    ga |= GACE_WRITE_DATA | GACE_APPEND_DATA;
  if (mode & S_IXGRP)
    ga |= GACE_EXECUTE;

  if (mode & S_IROTH)
    ea |= GACE_READ_DATA;
  if (mode & S_IWOTH)
    ea |= GACE_WRITE_DATA | GACE_APPEND_DATA;
  if (mode & S_IXOTH)
    ea |= GACE_EXECUTE;
  
  ap = acl_init(3);
  if (!ap)
    return NULL;

  if (gacl_create_entry_np(&ap, &ep, -1) < 0)
    goto Fail;
  ep->tag   = GACE_TAG_USER_OBJ;
  ep->perms = ua;
  ep->flags = 0;
  ep->type  = GACE_TYPE_ALLOW;

  if (gacl_create_entry_np(&ap, &ep, -1) < 0)
    goto Fail;
  ep->tag   = GACE_TAG_GROUP_OBJ;
  ep->perms = ga;
  ep->flags = 0;
  ep->type  = GACE_TYPE_ALLOW;

  if (gacl_create_entry_np(&ap, &ep, -1) < 0)
    goto Fail;
  ep->tag   = GACE_TAG_EVERYONE;
  ep->perms = ea;
  ep->flags = 0;
  ep->type  = GACE_TYPE_ALLOW;

  return ap;

 Fail:
  gacl_free(ap);
  return NULL;
}


int
_gacl_merge_permset(GACE_PERMSET *d,
		    GACE_PERMSET *s,
		    int f) {
  int i, a, rc, ec = 0;

  
  if (f == 0)
    gacl_clear_perms(d);

  for (i = 0; gace_p2c[i].c; i++) {
    a = gacl_get_perm_np(s, gace_p2c[i].p);
    if (a) {
      if (f > 0)
	rc = gacl_add_perm(d, gace_p2c[i].p);
      else if (f < 0)
	rc = gacl_delete_perm(d, gace_p2c[i].p);
      if (rc < 0)
	return rc;
      
      ec = 1;
    }
  }

  return ec;
}

int
_gacl_empty_permset(GACE_PERMSET *p) {
  int i, n;

  n = 0;
  for (i = 0; gace_p2c[i].c; i++) {
    if (gacl_get_perm_np(p, gace_p2c[i].p))
      ++n;
  }
  
  return n == 0;
}

int
_gacl_empty_flagset(GACE_FLAGSET *f) {
  int i, n;

  n = 0;
  for (i = 0; gace_f2c[i].c; i++) {
    if (gacl_get_flag_np(f, gace_f2c[i].f))
      ++n;
  }
  
  return n == 0;
}


int
_gacl_merge_flagset(GACE_FLAGSET *d,
		    GACE_FLAGSET *s,
		    int f) {
  int i, a, rc, ec = 0;


  if (f == 0)
    gacl_clear_flags_np(d);

  for (i = 0; gace_f2c[i].c; i++) {
    a = gacl_get_flag_np(s, gace_f2c[i].f);
    if (a) {
      if (f > 0)
	rc = gacl_add_flag_np(d, gace_f2c[i].f);
      else if (f < 0)
	rc = acl_delete_flag_np(d, gace_f2c[i].f);
      if (rc < 0)
	return rc;
      
      ec = 1;
    }
  }

  return ec;
}




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
  /* TODO: prepend or append ACEs? We append for now... */
  return gacl_create_entry_np(app, epp, -1);
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

static int
_gacl_entry_set_brand_np(GACE *ep,
			 GACL_BRAND b) {
  if (ep->brand != GACL_BRAND_NONE && ep->brand != b) {
    errno = EINVAL;
    return -1;
  }

  ep->brand = b;
  return 0;
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


/* 
 * Remove redundant ACL entries:
 * - Deny ACLs without permissions
 */
int
gacl_clean(GACL *ap) {
  int i, rc;
  GACE *ep;


 RESTART:
  for (i = 0; (rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1; i++) {
    GACE_PERMSET *ps;
    GACE_FLAGSET *fs;


    if (gacl_get_permset(ep, &ps) < 0)
      return -1;
    if (gacl_get_flagset_np(ep, &fs) < 0)
      return -1;

    if (_gacl_empty_permset(ps) && _gacl_empty_flagset(fs)) {
      if (gacl_delete_entry_np(ap, i) < 0)
	return -1;

      goto RESTART;
    }
  }

  return 0;
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

int
gacl_set_tag_type(GACE *ep,
		  GACE_TAG et) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }

  switch (et) {
  case ACL_USER_OBJ:
  case ACL_USER:
  case ACL_GROUP_OBJ:
  case ACL_GROUP:

  case ACL_MASK:
  case ACL_OTHER_OBJ:
    _gacl_entry_set_brand_np(ep, GACL_BRAND_POSIX);
    break;

  case ACL_EVERYONE:
    _gacl_entry_set_brand_np(ep, GACL_BRAND_NFS4);
    break;

  default:
    errno = EINVAL;
    return -1;
  }

  ep->tag = et;
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


/*
 * Delete an ACL from an object. 
 * We simulate that be stripping the ACL down to the bare owner@/group@/everyone@ entries
 */
int
gacl_delete_file_np(const char *path,
		   GACL_TYPE type) {
  GACL *ap;
  struct stat sb;
  int rc;


  if (stat(path, &sb) < 0)
    return -1;

  ap = _gacl_from_mode(sb.st_mode);
  if (!ap)
    return -1;

  rc = gacl_set_file(path, type, ap);
  gacl_free(ap);
  return rc;
}


/*
 * Delete an ACL from an object. 
 * We simulate that be stripping the ACL down to the bare owner@/group@/everyone@ entries
 */
int
gacl_delete_link_np(const char *path,
		    GACL_TYPE type) {
  GACL *ap;
  struct stat sb;
  int rc;


  if (lstat(path, &sb) < 0)
    return -1;

  ap = _gacl_from_mode(sb.st_mode);
  if (!ap)
    return -1;

  rc = gacl_set_link_np(path, type, ap);
  gacl_free(ap);
  return rc;
}


/*
 * Delete an ACL from an object. 
 * We simulate that be stripping the ACL down to the bare owner@/group@/everyone@ entries
 *
 * TODO: Replace that with an ACL created from the mode bits instead.
 */
int
gacl_delete_fd_np(int fd,
		  GACL_TYPE type) {
  GACL *ap;
  struct stat sb;
  int rc;


  if (fstat(fd, &sb) < 0)
    return -1;

  ap = _gacl_from_mode(sb.st_mode);
  if (!ap)
    return -1;

  rc = gacl_set_fd_np(fd, ap, type);
  gacl_free(ap);
  return rc;
}



/* TODO: To be implemented */

int
gacl_delete_def_file(const char *path) {
  errno = ENOSYS;
  return -1;
}

int
gacl_delete_def_link_np(const char *path) {
  errno = ENOSYS;
  return -1;
}


int
gacl_valid(GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_valid_fd_np(int fd, 
		 GACL_TYPE type, 
		 GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_valid_file_np(const char *path,
		   GACL_TYPE type,
		   GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_valid_link_np(const char *path,
		   GACL_TYPE type,
		   GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_calc_mask(GACL *ap) {
  errno = ENOSYS;
  return -1;
}


int
_gacl_permset_from_text(const char *buf,
			GACE_PERMSET *psp) {
  int i;
  char c;
  GACE_PERMSET nps = 0;


  if (!buf) {
    errno = EINVAL;
    return -1;
  }

  if (!*buf)
    return 0;

  if (strcasecmp(buf, "full_set") == 0 ||
      strcasecmp(buf, "all") == 0)
    nps = ACL_FULL_SET;
  else if (strcasecmp(buf, "modify_set") == 0 ||
	   strcasecmp(buf, "modify") == 0)
    nps = ACL_MODIFY_SET;
  else if (strcasecmp(buf, "write_set") == 0 ||
	   strcasecmp(buf, "write") == 0)
    nps = ACL_WRITE_SET;
  else if (strcasecmp(buf, "read_set") == 0 ||
	   strcasecmp(buf, "read") == 0)
    nps = ACL_READ_SET;
  else if (strcasecmp(buf, "empty_set") == 0 ||
	   strcasecmp(buf, "none") == 0)
    nps = 0;
  else {
    while ((c = *buf++) != '\0') {
      if (c == '-')
	continue;
      for (i = 0; gace_p2c[i].c && gace_p2c[i].c != c; i++)
	;
      if (!gace_p2c[i].c) {
	errno = EINVAL;
	return -1;
      }
      
      nps |= gace_p2c[i].p;
    }
    
  }

  *psp = nps;
  return 1;
}


int
_gacl_flagset_from_text(const char *buf,
		       GACE_FLAGSET *fsp) {
  int i;
  char c;
  GACE_FLAGSET nfs = 0;


  if (!buf) {
    errno = EINVAL;
    return -1;
  }

  if (!*buf)
    return 0;

  while ((c = *buf++) != '\0') {
    if (c == '-')
      continue;
    for (i = 0; gace_f2c[i].c && gace_f2c[i].c != c; i++)
      ;
    if (!gace_f2c[i].c) {
      errno = EINVAL;
      return -1;
    }

    nfs |= gace_f2c[i].f;
  }

  *fsp = nfs;
  return 1;
}


int
_gacl_entry_from_text(char *cp,
		      GACE *ep,
		      char *editchars) {
  char *np;
  int f_none;


  if (editchars) {
    if (strchr(editchars, *cp))
      ep->edit = *cp++;
    else
      ep->edit = 0;
  }
    
  /* 1. Get ACE tag (user:xxx, group:xxx, owner@, group@, everyone@ ) */
  np = strchr(cp, ':');
  if (!np) {
    errno = EINVAL;
    return -1;
  }
  *np++ = '\0';

  if (strcasecmp(cp, "user") == 0 || strcasecmp(cp, "u") == 0) {
    struct passwd *pp;
    uid_t uid;

    cp = np;
    np = strchr(cp, ':');
    if (!np) {
      errno = EINVAL;
      return -1;
    }
    *np++ = '\0';
    
    if (sscanf(cp, "%d", &uid) == 1) {
      ep->tag = GACE_TAG_USER;
      ep->id = uid;
    } else if ((pp = getpwnam(cp)) != NULL) {
      ep->tag = GACE_TAG_USER;
      ep->id = pp->pw_uid;
    } else {
      errno = EINVAL;
      return -1;
    }

  } else if (strcasecmp(cp, "group") == 0 || strcasecmp(cp, "g") == 0) {
    struct group *gp;
    gid_t gid;
    
    cp = np;
    np = strchr(cp, ':');
    if (!np) {
      errno = EINVAL;
      return -1;
    }
    *np++ = '\0';
    
    if (sscanf(cp, "%d", &gid) == 1) {
      ep->tag = GACE_TAG_GROUP;
      ep->id = gid;
    } else if ((gp = getgrnam(cp)) != NULL) {
      ep->tag = GACE_TAG_GROUP;
      ep->id = gp->gr_gid;
    } else {
      errno = EINVAL;
      return -1;
    }

  } else if (strcasecmp(cp, "owner@") == 0) {
    
    ep->tag = GACE_TAG_USER_OBJ;
    ep->id = -1;

  } else if (strcasecmp(cp, "group@") == 0) {
    
    ep->tag = GACE_TAG_GROUP_OBJ;
    ep->id = -1;

  } else if (strcasecmp(cp, "everyone@") == 0) {

    ep->tag = GACE_TAG_EVERYONE;
    ep->id = -1;

  } else {

    /* Attempt to autodetect user/group - must be unique user/group name or uid/gid to work! */
    struct passwd *pp;
    struct group *gp;
    uid_t id;
    
    
    if (sscanf(cp, "%d", &id) == 1) {
      pp = getpwuid(id);
      gp = getgrgid(id);
    } else {
      pp = getpwnam(cp);
      gp = getgrnam(cp);
    }

    if (pp && gp) {
      errno = EINVAL;
      return -1;
    }

    if (pp) {
      ep->tag = GACE_TAG_USER;
      ep->id = pp->pw_uid;
    } else if (gp) {
      ep->tag = GACE_TAG_GROUP;
      ep->id = gp->gr_gid;
    } else {
      errno = EINVAL;
      return -1;
    }

  }


  /* 2. Get permset */
  cp = np;
  np = strchr(cp, ':');
  if (np)
    *np++ = '\0';
  
  f_none = (strcasecmp(cp, "none") == 0);

  if (_gacl_permset_from_text(cp, &ep->perms) < 0)
    return -1;
  cp = np;


  /* 3. Get flagset */
  if (cp) {
    np = strchr(cp, ':');
    if (np)
      *np++ = '\0';
    /* Parse flags in cp */
    if (_gacl_flagset_from_text(cp, &ep->flags) < 0)
      return -1;
  } else
    ep->flags = 0;

  cp = np;
  /* 4. Get type (allow, deny, alarm, audit) */
  if (cp) {
    np = strchr(cp, ':');
    if (np) {
      errno = EINVAL;
      return -1;
    }
    if (strcasecmp(cp, "allow") == 0) 
      ep->type = GACE_TYPE_ALLOW;
    else if (strcasecmp(cp, "deny") == 0)
      ep->type = GACE_TYPE_DENY;
    else if (strcasecmp(cp, "audit") == 0)
      ep->type = GACE_TYPE_AUDIT;
    else if (strcasecmp(cp, "alarm") == 0)
      ep->type = GACE_TYPE_ALARM;
    else {
      errno = EINVAL;
      return -1;
    }
  } else {
    if (f_none) {
      ep->perms = GACE_FULL_SET;
      ep->type = GACE_TYPE_DENY;
    } else 
      ep->type = GACE_TYPE_ALLOW;
  }

  return 0;
}


GACL *
gacl_from_text(const char *buf) {
  GACL *ap;
  char *bp, *tbuf, *es;


  bp = tbuf = strdup(buf);

  ap = gacl_init(GACL_MAX_ENTRIES);
  if (!ap) {
    free(tbuf);
    return NULL;
  }

  while ((es = strsep(&bp, ", \t\n\r")) != NULL) {
    GACE *ep;

    if (gacl_create_entry_np(&ap, &ep, -1) < 0)
      goto Fail;

    if (_gacl_entry_from_text(es, ep, "+-=") < 0)
      goto Fail;
  }

  return ap;

 Fail:
  gacl_free(ap);
  errno = EINVAL;
  return NULL;
}


/* ----- OS-specific stuff below here -------------- */

#ifdef __linux__
#include <arpa/inet.h>
#include <attr/xattr.h>
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
    char *bp, *t;
    bp = buf;

    t = strsep(&bp, " \t\n");
    if (!t)
      continue;
    if (strcmp(t, "Domain") == 0) {
      t = strsep(&bp, " \t\n");
      if (!t || strcmp(t, "=") != 0)
	continue;
      t = strsep(&bp, " \t\n");
      if (!t) {
	fclose(fp);
	return NULL;
      }
	
      saved_domain = strdup(t);
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
#endif

#ifdef __sun__
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

#endif
