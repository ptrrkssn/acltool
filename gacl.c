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

#include "strings.h"

#define GACL_C_INTERNAL 1
#include "gacl.h"
#include "gacl_impl.h"

#include "vfs.h"

static struct gace_perm2c {
  int p;
  char c;
  char *s;
} gace_p2c[] = {
		{ GACL_PERM_READ_DATA, 'r', "read_data" },
		{ GACL_PERM_WRITE_DATA, 'w', "write_data" },
		{ GACL_PERM_EXECUTE, 'x', "execute" },
		{ GACL_PERM_APPEND_DATA, 'p', "append_data" },
		{ GACL_PERM_DELETE_CHILD, 'D', "delete_child" },
		{ GACL_PERM_DELETE, 'd', "delete" },
		{ GACL_PERM_READ_ATTRIBUTES, 'a', "read_attributes" },
		{ GACL_PERM_WRITE_ATTRIBUTES, 'A', "write_attributes" },
		{ GACL_PERM_READ_NAMED_ATTRS, 'R', "read_xattrs" },
		{ GACL_PERM_WRITE_NAMED_ATTRS, 'W', "write_xattrs" },
		{ GACL_PERM_READ_ACL, 'c', "read_acl" },
		{ GACL_PERM_WRITE_ACL, 'C', "write_acl" },
		{ GACL_PERM_WRITE_OWNER, 'o', "write_owner" },
		{ GACL_PERM_SYNCHRONIZE, 's', "synchronize" },
		{ 0, 0 }
};

static struct gace_flag2c {
  int f;
  char c;
} gace_f2c[] = {
		{ GACL_FLAG_FILE_INHERIT, 'f' },
		{ GACL_FLAG_DIRECTORY_INHERIT, 'd' },
		{ GACL_FLAG_INHERIT_ONLY, 'i' },
		{ GACL_FLAG_NO_PROPAGATE_INHERIT, 'n' },
		{ GACL_FLAG_SUCCESSFUL_ACCESS, 'S' },
		{ GACL_FLAG_FAILED_ACCESS, 'F' },
#ifdef GACL_FLAG_INHERITED
		{ GACL_FLAG_INHERITED, 'I' },
#endif
		{ 0, 0 }
};



/* Generate an ACL from Unix mode bits */
GACL *
_gacl_from_mode(mode_t mode) {
  GACL *ap;
  GACL_ENTRY *ep;
  GACL_PERM ua, ga, ea;


  ua = ga = ea = GACL_PERM_READ_ACL | GACL_PERM_READ_ATTRIBUTES | GACL_PERM_READ_NAMED_ATTRS | GACL_PERM_SYNCHRONIZE;
  ua |= GACL_PERM_WRITE_ACL | GACL_PERM_WRITE_OWNER | GACL_PERM_WRITE_ATTRIBUTES | GACL_PERM_WRITE_NAMED_ATTRS;

  if (mode & S_IRUSR)
    ua |= GACL_PERM_READ_DATA;
  if (mode & S_IWUSR)
    ua |= GACL_PERM_WRITE_DATA | GACL_PERM_APPEND_DATA;
  if (mode & S_IXUSR)
    ua |= GACL_PERM_EXECUTE;

  if (mode & S_IRGRP) 
    ga |= GACL_PERM_READ_DATA;
  if (mode & S_IWGRP)
    ga |= GACL_PERM_WRITE_DATA | GACL_PERM_APPEND_DATA;
  if (mode & S_IXGRP)
    ga |= GACL_PERM_EXECUTE;

  if (mode & S_IROTH)
    ea |= GACL_PERM_READ_DATA;
  if (mode & S_IWOTH)
    ea |= GACL_PERM_WRITE_DATA | GACL_PERM_APPEND_DATA;
  if (mode & S_IXOTH)
    ea |= GACL_PERM_EXECUTE;
  
  ap = gacl_init(3);
  if (!ap)
    return NULL;

  if (gacl_create_entry_np(&ap, &ep, -1) < 0)
    goto Fail;
  ep->tag.type = GACL_TAG_TYPE_USER_OBJ;
  ep->perms = ua;
  ep->flags = 0;
  ep->type  = GACL_ENTRY_TYPE_ALLOW;

  if (gacl_create_entry_np(&ap, &ep, -1) < 0)
    goto Fail;
  ep->tag.type = GACL_TAG_TYPE_GROUP_OBJ;
  ep->perms = ga;
  ep->flags = 0;
  ep->type  = GACL_ENTRY_TYPE_ALLOW;

  if (gacl_create_entry_np(&ap, &ep, -1) < 0)
    goto Fail;
  ep->tag.type = GACL_TAG_TYPE_EVERYONE;
  ep->perms = ea;
  ep->flags = 0;
  ep->type  = GACL_ENTRY_TYPE_ALLOW;

  return ap;

 Fail:
  gacl_free(ap);
  return NULL;
}


int
gacl_merge_permset(GACL_PERMSET *d,
		   GACL_PERMSET *s,
		   int f) {
  int i, a, rc, ec = 0;

  
  if (f == 0)
    gacl_clear_perms(d);

  for (i = 0; gace_p2c[i].c; i++) {
    a = gacl_get_perm_np(s, gace_p2c[i].p);
    if (a) {
      rc = 0;
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
gacl_empty_permset(GACL_PERMSET *p) {
  int i, n;

  n = 0;
  for (i = 0; gace_p2c[i].c; i++) {
    if (gacl_get_perm_np(p, gace_p2c[i].p))
      ++n;
  }
  
  return n == 0;
}

int
gacl_empty_flagset(GACL_FLAGSET *f) {
  int i, n;

  n = 0;
  for (i = 0; gace_f2c[i].c; i++) {
    if (gacl_get_flag_np(f, gace_f2c[i].f))
      ++n;
  }
  
  return n == 0;
}


int
gacl_merge_flagset(GACL_FLAGSET *d,
		   GACL_FLAGSET *s,
		   int f) {
  int i, a, rc, ec = 0;


  if (f == 0)
    gacl_clear_flags_np(d);

  for (i = 0; gace_f2c[i].c; i++) {
    a = gacl_get_flag_np(s, gace_f2c[i].f);
    if (a) {
      rc = 0;
      if (f > 0)
	rc = gacl_add_flag_np(d, gace_f2c[i].f);
      else if (f < 0)
	rc = gacl_delete_flag_np(d, gace_f2c[i].f);
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

  
  if (count < GACL_MIN_ENTRIES)
    count = GACL_DEFAULT_ENTRIES;
  
  s = sizeof(*ap) + count*sizeof(ap->av[0]);
  ap = malloc(s);
  if (!ap)
    return NULL;

  ap->type = 0;
  ap->owner[0] = '\0';
  ap->group[0] = '\0';
  ap->ac = 0;
  ap->ap = 0;
  ap->as = count;

  return ap;
}


int
gacl_free(void *op) {
  if (op)
    free(op);
  return 0;
}


int
gacl_init_entry(GACL_ENTRY *ep) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }
    
  memset(ep, 0, sizeof(*ep));
  return 0;
}

int
gacl_copy_entry(GACL_ENTRY *dep,
		GACL_ENTRY *sep) {
  if (!dep || !sep || dep == sep) {
    errno = EINVAL;
    return -1;
  }
  
  *dep = *sep;
  return 0;
}

int
_gacl_entries(GACL *ap) {
  return ap->ac;
}

int
_gacl_get_entry(GACL *ap,
		int pos,
		GACL_ENTRY **epp) {
  if (!ap || pos < 0 || pos > ap->ac) {
    errno = EINVAL;
    return -1;
  }
  
  ap->ap = pos;

  if (ap->ap >= ap->ac) {
    return 0;
  }

  *epp = &ap->av[ap->ap++];
  return 1;
}

int
gacl_get_entry(GACL *ap,
	       int eid,
	       GACL_ENTRY **epp) {
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
/* TODO: Realloc() GACL if need to extent to make room for more GACL_ENTRYs */
int
gacl_create_entry_np(GACL **app,
		     GACL_ENTRY **epp,
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
		  GACL_ENTRY **epp) {
  /* TODO: prepend or append ACEs? We append for now... */
  return gacl_create_entry_np(app, epp, -1);
}


int
gacl_add_entry_np(GACL **app,
		  GACL_ENTRY *ep,
		  int index) {
  GACL_ENTRY *nep;
  
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
		  GACL_ENTRY *ep) {
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


/* 
 * Remove redundant ACL entries:
 * - Deny ACLs without permissions
 */
int
gacl_clean(GACL *ap) {
  int i, rc;
  GACL_ENTRY *ep;


 RESTART:
  for (i = 0; (rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1; i++) {
    GACL_PERMSET *ps;
    GACL_FLAGSET *fs;


    if (gacl_get_permset(ep, &ps) < 0)
      return -1;
    if (gacl_get_flagset_np(ep, &fs) < 0)
      return -1;

    if (gacl_empty_permset(ps) && gacl_empty_flagset(fs)) {
      if (gacl_delete_entry_np(ap, i) < 0)
	return -1;

      goto RESTART;
    }
  }

  return 0;
}


/* Compare two ACL Entries */
static int
_gacl_entry_compare(const void *va,
		    const void *vb) {
  GACL_ENTRY *a = (GACL_ENTRY *) va;
  GACL_ENTRY *b = (GACL_ENTRY *) vb;
  GACL_ENTRY_TYPE aet_a, aet_b;
  GACL_TAG_TYPE ta, tb;
  GACL_FLAGSET *afs, *bfs;
  int v;
  int inherited_a, inherited_b;
  int inherit_only_a, inherit_only_b;
  uid_t *qa, *qb;
  

  gacl_get_flagset_np(a, &afs);
  gacl_get_flagset_np(b, &bfs);
  
  inherited_a = gacl_get_flag_np(afs, GACL_FLAG_INHERITED);
  inherited_b = gacl_get_flag_np(bfs, GACL_FLAG_INHERITED);

  /* Explicit entries goes before inherited ones */
  v = inherited_a-inherited_b;
  if (v)
    return v;

  
  inherit_only_a = gacl_get_flag_np(afs, GACL_FLAG_INHERIT_ONLY);
  inherit_only_b = gacl_get_flag_np(bfs, GACL_FLAG_INHERIT_ONLY);

  /* Ignore this entry if the 'inherit_only' flag is set on one of them */
  if (inherit_only_a || inherit_only_b)
    return 0;

  
  /* order: owner@ - user - group@ - group - everyone@ */
  if (gacl_get_tag_type(a, &ta) < 0)
    return -1;
  
  if (gacl_get_tag_type(b, &tb) < 0)
    return 1;

  v = ta-tb;
  if (v)
    return v;

  switch (ta) {
  case GACL_TAG_TYPE_USER:
    qa = (uid_t *) gacl_get_qualifier(a);
    qb = (uid_t *) gacl_get_qualifier(b);
    v = (*qa-*qb);
    gacl_free((void *) qa);
    gacl_free((void *) qb);
    if (v)
      return v;
    break;
    
  case GACL_TAG_TYPE_GROUP:
    qa = (uid_t *) gacl_get_qualifier(a);
    qb = (uid_t *) gacl_get_qualifier(b);
    v = (*qa-*qb);
    gacl_free((void *) qa);
    gacl_free((void *) qb);
    if (v)
      return v;
    break;

  default:
    break;
  }
  
  /* Deny entries goes before allow ones */
  if (gacl_get_entry_type_np(a, &aet_a) < 0)
    return -1;
  
  if (gacl_get_entry_type_np(b, &aet_b) < 0)
    return 1;

  v = aet_b - aet_a;
  if (v)
    return v;

  return 0;
}


/* 
 * foreach CLASS (implicit, inherited)
 *   foreach TAG (owner@, user:uid, group@, group:gid, everyone@)
 *     foreach ID (x)
 *       foreach TYPE (deny, allow)
 */
GACL *
gacl_sort(GACL *ap) {
  GACL *nap;


  nap = gacl_dup(ap);
  if (!nap)
    return NULL;

  qsort(&nap->av[0], nap->ac, sizeof(nap->av[0]), _gacl_entry_compare);
  return nap;
}



GACL *
gacl_merge(GACL *ap) {
  GACL *nap;
  int i, j, n;
  

  nap = gacl_dup(ap);
  if (!nap)
    return NULL;

  n = 0;
  for (i = 0; i < nap->ac; i++) {
  AGAIN:
    for (j = i+1; j < nap->ac && _gacl_entry_compare(&nap->av[i], &nap->av[j]) != 0; j++)
      ;

    if (j < nap->ac) {
      /* Match found - merge ACE */
      GACL_PERMSET *ps_a, *ps_b;
      GACL_FLAGSET *fs_a, *fs_b;
      
      if (gacl_get_permset(&nap->av[i], &ps_a) < 0 ||
	  gacl_get_permset(&nap->av[j], &ps_b) < 0)
	goto Fail;
      
      if (gacl_get_flagset_np(&nap->av[i], &fs_a) < 0 ||
	  gacl_get_flagset_np(&nap->av[j], &fs_b) < 0)
	goto Fail;

      if (gacl_merge_permset(ps_a, ps_b, +1) < 0)
	goto Fail;

      if (gacl_merge_flagset(fs_a, fs_b, +1) < 0)
	goto Fail;

      gacl_delete_flag_np(fs_a, GACL_FLAG_INHERITED);
      
      if (gacl_set_permset(&nap->av[i], ps_a) < 0)
	goto Fail;
      
      if (gacl_set_flagset_np(&nap->av[i], fs_a) < 0)
	goto Fail;
      
      if (gacl_delete_entry_np(nap, j) < 0)
	goto Fail;

      ++n;
      goto AGAIN;
    }
  }

  return nap;

 Fail:
  gacl_free(nap);
  return NULL;
}


int
gacl_is_trivial_np(GACL *ap,
		   int *trivialp) {
  GACL_ENTRY *ep;
  GACL_TAG_TYPE t;
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
      case GACL_TAG_TYPE_USER_OBJ:
      case GACL_TAG_TYPE_GROUP_OBJ:
      case GACL_TAG_TYPE_EVERYONE:
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
  GACL_ENTRY *ep;
  GACL_TAG_TYPE t;
  int i, rc;
  
  
  nap = gacl_init(ap->as);
  if (!nap)
    return NULL;
  
  for (i = 0; (rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1; i++) {
    if (gacl_get_tag_type(ep, &t) < 0)
      return NULL;

    switch (t) {
    case GACL_TAG_TYPE_USER_OBJ:
    case GACL_TAG_TYPE_GROUP_OBJ:
    case GACL_TAG_TYPE_EVERYONE:
      gacl_add_entry_np(&nap, ep, -1);
      break;
    default:
      break;
    }

  }

  return nap;
}


int
_gacl_entry_match(GACL_ENTRY *aep,
		  GACL_ENTRY *mep,
		  int how) {
  GACL_TAG_TYPE att, mtt;
  GACL_PERMSET *apsp, *mpsp;
  GACL_FLAGSET *afsp, *mfsp;
  GACL_ENTRY_TYPE aet, met;
  
  
  if (!aep || !mep) {
    errno = EINVAL;
    return -1;
  }

  
  /* 1. ACE tag type (owner@, group@, everyone@, user:xx, group:xxx) */
  if (gacl_get_tag_type(aep, &att) < 0)
    return -1;
  
  if (gacl_get_tag_type(mep, &mtt) < 0)
    return -1;

  if (att != mtt)
    return 0;

  if (att == GACL_TAG_TYPE_USER || att == GACL_TAG_TYPE_GROUP) {
    uid_t *qa = (uid_t *) gacl_get_qualifier(aep);
    uid_t *qb = (uid_t *) gacl_get_qualifier(mep);
    
    if ((!qa && qb) || (qa && !qb) || (*qa != *qb)) {
      if (qa)
	gacl_free(qa);
      if (qb)
	gacl_free(qb);
      return 0;
    }
    if (qa)
      gacl_free(qa);
    if (qb)
      gacl_free(qb);
  }
  
  /* 2. ACE entry type (allow, deny, audit, alarm) */
  if (gacl_get_entry_type_np(aep, &aet) < 0)
    return -1;
  
  if (gacl_get_entry_type_np(mep, &met) < 0)
    return -1;
  
  if (aet != met)
    return 0;

  
  /* 3. ACE permissions */
  if (gacl_get_permset(aep, &apsp) < 0)
    return -1;
  
  if (gacl_get_permset(mep, &mpsp) < 0)
    return -1;

  switch (how) {
  case 0:
  case '=':
  case '^':
    if (*apsp != *mpsp)
      return 0;
    break;
    
  case '+': /* Match if all permissions in B is set in A */
    if ((*apsp & *mpsp) != *mpsp)
      return 0;
    break;

  case '-': /* Match if all permissions in B is unset in A */
    if ((*apsp & *mpsp) != 0)
      return 0;
    break;

  default:
    errno = EINVAL;
    return -1;
  }
  
  /* 4. ACE flags */
  if (gacl_get_flagset_np(aep, &afsp) < 0)
    return -1;
  
  if (gacl_get_flagset_np(mep, &mfsp) < 0)
    return -1;
  
  switch (how) {
  case 0:
  case '=':
  case '^':
    if (*afsp != *mfsp)
      return 0;
    break;

  case '+':
    if ((*afsp & *mfsp) != *mfsp)
      return 0;
    break;

  case '-':
    if ((*afsp & *mfsp) != 0)
      return 0;
    break;

  default:
    errno = EINVAL;
    return -1;
  }
  
  return 1;
}

int
gacl_entry_match(GACL_ENTRY *aep,
		 GACL_ENTRY *mep) {
  return _gacl_entry_match(aep, mep, 0);
}


int
gacl_match(GACL *ap,
	   GACL *mp) {
  GACL_ENTRY *aep, *mep;
  int p, arc, mrc;

  
  if (ap->ac != mp->ac)
    return 0;

  if (ap->type != mp->type)
    return 0;
  
  p = GACL_FIRST_ENTRY;
  while ((arc = gacl_get_entry(ap, p, &aep)) == 1 && (mrc = gacl_get_entry(mp, p, &mep)) == 1) {
    int rc;

    p = GACL_NEXT_ENTRY;

    rc = gacl_entry_match(aep, mep);
    if (rc != 1)
      return rc;
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
_gacl_get_tag(GACL_ENTRY *ep,
	      GACL_TAG *etp) {
  if (!ep || !etp) {
    errno = EINVAL;
    return -1;
  }

  *etp = ep->tag;
  return 0;
}


int
_gacl_set_tag(GACL_ENTRY *ep,
	      GACL_TAG *etp) {
  if (!ep || !etp) {
    errno = EINVAL;
    return -1;
  }

  ep->tag.type = etp->type;
  ep->tag.ugid = etp->ugid;

  if (ep->tag.name)
    free(ep->tag.name);
  
  ep->tag.name = s_dup(etp->name);
  return 0;
}


/* 
 * Get ACE tag (user:xxx, group:xxx, owner@, group@, everyone@ )
 *
 * Format: 
 * [{user|group}:]<name>[:]
 */
int
_gacl_entry_tag_from_text(GACL_ENTRY *ep,
			  char **bufp,
			  int flags) {
  struct passwd *pp;
  struct group *gp;
  char *np, *cp = *bufp;
  GACL_TAG *etp = &ep->tag;

  
  if (strncasecmp(cp, "user:", 5) == 0 || strncasecmp(cp, "u:", 2) == 0) {
    etp->type = GACL_TAG_TYPE_USER;

    cp = strchr(cp, ':')+1;
    
    /* Locate end of tag */
    np = cp;
    while (*np && *np != ':')
      ++np;
    
    if (sscanf(cp, "%d", &etp->ugid) == 1) {
      
      pp = getpwuid(etp->ugid);
      if (pp)
	etp->name = s_dup(pp->pw_name);
      else {
	if (flags & GACL_TEXT_RELAXED)
	  etp->name = s_ndup(cp, np-cp);
	else {
	  errno = EINVAL;
	  return -1;
	}
      }
      
    } else {
      
      etp->name = s_ndup(cp, np-cp);
      if ((pp = getpwnam(etp->name)) != NULL)
	etp->ugid = pp->pw_uid;
      else {
	if (flags & GACL_TEXT_RELAXED)	
	  etp->ugid = -1;
	else {
	  errno = EINVAL;
	  return -1;
	}
      }
      
    } 
    
    if (*np)
      ++np;
    
    *bufp = np;
    return 0;
  }

  if (strncasecmp(cp, "group:", 6) == 0 || strncasecmp(cp, "g:", 2) == 0) {
    etp->type = GACL_TAG_TYPE_GROUP;
    
    cp = strchr(cp, ':')+1;
    
    /* Locate end of tag */
    np = cp;
    while (*np && *np != ':')
      ++np;
    
    if (sscanf(cp, "%d", &etp->ugid) == 1) {
      
      gp = getgrgid(etp->ugid);
      if (gp)
	etp->name = s_dup(gp->gr_name);
      else {
	if (flags & GACL_TEXT_RELAXED)	
	  etp->name = s_ndup(cp, np-cp);
	else {
	  errno = EINVAL;
	  return -1;
	}
      }
      
    } else {
      etp->name = s_ndup(cp, np-cp);
      if ((gp = getgrnam(etp->name)) != NULL)
	etp->ugid = gp->gr_gid;
      else {
	if (flags & GACL_TEXT_RELAXED)	
	  etp->ugid = -1;
	else {
	  errno = EINVAL;
	  return -1;
	}
      }
      
    }
    
    if (*np)
      ++np;
    
    *bufp = np;
    return 0;
  }


  /* Locate end of tag */
  np = strchr(cp, ':');

  etp->name = s_ndup(cp, np-cp);
  if (!etp->name) {
    errno = EINVAL;
    return -1;
  }

  if (np)
    ++np;
  
  if (strcasecmp(etp->name, "owner@") == 0) {
    etp->type = GACL_TAG_TYPE_USER_OBJ;
    etp->ugid = -1;

    *bufp = np;
    return 0;
  }

  if (strcasecmp(etp->name, "group@") == 0) {
    etp->type = GACL_TAG_TYPE_GROUP_OBJ;
    etp->ugid = -1;
    
    *bufp = np;
    return 0;
  }

  if (strcasecmp(etp->name, "everyone@") == 0) {
    etp->type = GACL_TAG_TYPE_EVERYONE;
    etp->ugid = -1;

    *bufp = np;
    return 0;
  } 

  /* 
   * Attempt to autodetect user/group - must be unique 
   * user/group name or uid/gid to work!
   */
  etp->ugid = -1;
  if (sscanf(etp->name, "%d", &etp->ugid) == 1) {
    pp = getpwuid(etp->ugid);
    gp = getgrgid(etp->ugid);
  } else {
    pp = getpwnam(etp->name);
    gp = getgrnam(etp->name);
  }
  
  if (pp && gp) {
    errno = EINVAL;
    return -1;
  }
  
  if (pp) {
    etp->type = GACL_TAG_TYPE_USER;
    etp->ugid = pp->pw_uid;
  } else if (gp) {
    etp->type = GACL_TAG_TYPE_GROUP;
    etp->ugid = gp->gr_gid;
  } else {
    if (flags & GACL_TEXT_RELAXED)
      etp->type = GACL_TAG_TYPE_UNKNOWN;
    else {
      errno = EINVAL;
      return -1;
    }
  }

  *bufp = np;
  return 0;
}


int
gacl_get_tag_type(GACL_ENTRY *ep,
		  GACL_TAG_TYPE *ettp) {
  if (!ep || !ettp) {
    errno = EINVAL;
    return -1;
  }

  *ettp = ep->tag.type;
  return 0;
}

int
gacl_set_tag_type(GACL_ENTRY *ep,
		  GACL_TAG_TYPE et) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }

  ep->tag.type = et;
  return 0;
}

void *
gacl_get_qualifier(GACL_ENTRY *ep) {
  uid_t *idp;


  if (!ep) {
    errno = EINVAL;
    return NULL;
  }

  switch (ep->tag.type) {
  case GACL_TAG_TYPE_USER:
  case GACL_TAG_TYPE_GROUP:
    idp = malloc(sizeof(*idp));
    if (!idp)
      return NULL;

    *idp = ep->tag.ugid;
    return (void *) idp;

  default:
    errno = EINVAL;
    return NULL;
  }
}

int
gacl_set_qualifier(GACL_ENTRY *ep,
		   const void *qp) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }

  switch (ep->tag.type) {
  case GACL_TAG_TYPE_USER:
  case GACL_TAG_TYPE_GROUP:
    ep->tag.ugid = * (uid_t *) qp;
    return 0;

  default:
    errno = EINVAL;
    return -1;
  }
}


int
gacl_get_permset(GACL_ENTRY *ep,
		 GACL_PERMSET **pspp) {
  if (!ep || !pspp) {
    errno = EINVAL;
    return -1;
  }

  *pspp = &ep->perms;
  return 0;
}


int
gacl_set_permset(GACL_ENTRY *ep,
		 GACL_PERMSET *psp) {
  if (!ep || !psp) {
    errno = EINVAL;
    return -1;
  }

  ep->perms = *psp;
  return 0;
}


int
gacl_get_perm_np(GACL_PERMSET *epp,
		 GACL_PERM p) {
  if (!epp) {
    errno = EINVAL;
    return -1;
  }

  return (*epp & p) ? 1 : 0;
}

int
gacl_clear_perms(GACL_PERMSET *psp) {
  if (!psp) {
    errno = EINVAL;
    return -1;
  }
  
  *psp = 0;
  return 0;
}


int
gacl_add_perm(GACL_PERMSET *psp,
	      GACL_PERM p) {
  if (!psp) {
    errno = EINVAL;
    return -1;
  }

  *psp |= p;
  return 0;
}

int
gacl_delete_perm(GACL_PERMSET *psp,
		 GACL_PERM p) {
  if (!psp) {
    errno = EINVAL;
    return -1;
  }

  *psp &= ~p;
  return 0;
}


int
gacl_get_flagset_np(GACL_ENTRY *ep,
		    GACL_FLAGSET **fspp) {
  if (!ep || !fspp) {
    errno = EINVAL;
    return -1;
  }

  *fspp = &ep->flags;
  return 0;
}

int
gacl_set_flagset_np(GACL_ENTRY *ep,
		    GACL_FLAGSET *fsp) {
  if (!ep || !fsp) {
    errno = EINVAL;
    return -1;
  }

  ep->flags = *fsp;
  return 0;
}

int
gacl_clear_flags_np(GACL_FLAGSET *fsp) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }
  
  *fsp = 0;
  return 0;
}

int
gacl_get_flag_np(GACL_FLAGSET *fsp,
		 GACL_FLAG f) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }

  return (*fsp & f) ? 1 : 0;
}

int
gacl_add_flag_np(GACL_FLAGSET *fsp,
		 GACL_FLAG f) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }

  *fsp |= f;
  return 0;
}

int
gacl_delete_flag_np(GACL_FLAGSET *fsp,
		    GACL_FLAG f) {
  if (!fsp) {
    errno = EINVAL;
    return -1;
  }

  *fsp &= ~f;
  return 0;
}


int
gacl_get_entry_type_np(GACL_ENTRY *ep,
		       GACL_ENTRY_TYPE *etp) {
  if (!ep || !etp) {
    errno = EINVAL;
    return -1;
  }

  *etp = ep->type;
  return 0;
}


int
gacl_set_entry_type_np(GACL_ENTRY *ep,
		       GACL_ENTRY_TYPE et) {
  if (!ep) {
    errno = EINVAL;
    return -1;
  }

  ep->type = et;
  return 0;
}



ssize_t
gacl_entry_tag_to_text(GACL_ENTRY *ep,
		       char *buf,
		       size_t bufsize,
		       int flags) {
  GACL_TAG_TYPE et;

  
  if (gacl_get_tag_type(ep, &et) < 0)
    return -1;

  if (et == GACL_TAG_TYPE_USER) {
    return snprintf(buf, bufsize, "user:%s", ep->tag.name);
  } else if (et == GACL_TAG_TYPE_GROUP) {
    return snprintf(buf, bufsize, "group:%s", ep->tag.name);
  } else
    return snprintf(buf, bufsize, "%s", ep->tag.name);
  
  errno = EINVAL;
  return -1;
}


ssize_t
gacl_entry_permset_to_text(GACL_ENTRY *ep,
			   char *buf,
			   size_t bufsize,
			   int flags) {
  GACL_PERMSET *epsp;
  GACL_PERM p;
  int a, n;

  
  if (gacl_get_permset(ep, &epsp) < 0)
    return -1;

  n = 0;
  for (p = 0; bufsize > 1 && gace_p2c[p].c; p++) {
    a = gacl_get_perm_np(epsp, gace_p2c[p].p);
    if (a < 0) {
      *buf = 0;
      return -1;
    }
    if (a || !(flags & GACL_TEXT_COMPACT)) {
      *buf++ = (a ? gace_p2c[p].c : '-');
      bufsize--;
      n++;
    }
  }
  *buf = '\0';

  return n;
}


ssize_t
gacl_entry_flagset_to_text(GACL_ENTRY *ep,
			   char *buf,
			   size_t bufsize,
			   int flags) {
  GACL_FLAGSET *efsp;
  GACL_FLAG f;
  int a, n;

  
  if (gacl_get_flagset_np(ep, &efsp) < 0)
    return -1;

  n = 0;
  for (f = 0; bufsize > 1 && gace_f2c[f].c; f++) {
    a = gacl_get_flag_np(efsp, gace_f2c[f].f);
    if (a < 0)
      return -1;
    if (a || !(flags & GACL_TEXT_COMPACT)) {
      *buf++ = (a ? gace_f2c[f].c : '-');
      bufsize--;
      n++;
    }
  }
  *buf = '\0';

  return n;
}


ssize_t
gacl_entry_type_to_text(GACL_ENTRY *ep,
			char *buf,
			size_t bufsize,
			int flags) {
  GACL_ENTRY_TYPE et;

  
  if (gacl_get_entry_type_np(ep, &et) < 0)
    return -1;
  
  switch (et) {
  case GACL_ENTRY_TYPE_UNDEFINED:
    return 0;
  case GACL_ENTRY_TYPE_ALLOW:
    return snprintf(buf, bufsize, "allow");
  case GACL_ENTRY_TYPE_DENY:
    return snprintf(buf, bufsize, "deny");
  case GACL_ENTRY_TYPE_ALARM:
    return snprintf(buf, bufsize, "alarm");
  case GACL_ENTRY_TYPE_AUDIT:
    return snprintf(buf, bufsize, "audit");
  }

  errno = EINVAL;
  return -1;
}



ssize_t
gacl_entry_to_text(GACL_ENTRY *ep,
		   char *buf,
		   size_t bufsize,
		   int flags) {
  char *bp;
  ssize_t rc;
  GACL_FLAGSET *efsp;
  
  bp = buf;
  
  rc = gacl_entry_tag_to_text(ep, bp, bufsize, flags);
  if (rc < 0) {
    puts("A");
    return -1;
  }
  bp += rc;
  bufsize -= rc;

  if (bufsize <= 1) {
    puts("B");
    return -1;
  }
  
  *bp++ = ':';
  *bp = '\0';
  bufsize--;

  rc = gacl_entry_permset_to_text(ep, bp, bufsize, flags);
  if (rc < 0) {
    puts("C");
    return -1;
  }
  bp += rc;
  bufsize -= rc;

  if ((ep->flags && ep->type != GACL_ENTRY_TYPE_ALLOW) ||
      !(flags & GACL_TEXT_COMPACT) ||
      (gacl_get_flagset_np(ep, &efsp) == 0 && !gacl_empty_flagset(efsp))) {
    if (bufsize <= 1) {
      puts("D");
      return -1;
    }
    
    *bp++ = ':';
    *bp = '\0';
    bufsize--;
    
    rc = gacl_entry_flagset_to_text(ep, bp, bufsize, flags);
    if (rc < 0) {
      puts("E");
      return -1;
    }
    
    bp += rc;
    bufsize -= rc;
    
    if (bufsize <= 1)
      return -1;
    
    if ((ep->flags && ep->type != GACL_ENTRY_TYPE_ALLOW) || !(flags & GACL_TEXT_COMPACT)) {
      *bp++ = ':';
      *bp = '\0';
      bufsize--;
      
      if (ep->type != GACL_ENTRY_TYPE_ALLOW || !(flags & GACL_TEXT_COMPACT)) {
	rc = gacl_entry_type_to_text(ep, bp, bufsize, flags);
	if (rc < 0) {
	  puts("F");
	  return -1;
	}
	
	bp += rc;
	bufsize -= rc;
      }
    }
  }
  
  if (flags & GACL_TEXT_APPEND_ID) {
    GACL_TAG_TYPE et;
    
    if (gacl_get_tag_type(ep, &et) < 0)
      return -1;

    rc = 0;
    switch (et) {
    case GACL_TAG_TYPE_USER:
      rc = snprintf(bp, bufsize, "\t# uid=%d", ep->tag.ugid);
      break;
    case GACL_TAG_TYPE_GROUP:
      rc = snprintf(bp, bufsize, "\t# gid=%d", ep->tag.ugid);
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

int
_gacl_max_tagwidth(GACL *ap) {
  int i;


  int mw = 0;
  for (i = 0; i < ap->ac; i++) {
    GACL_ENTRY *ep = &ap->av[i];
    int ew = 0;
    
    switch (ep->tag.type) {
    case GACL_TAG_TYPE_USER_OBJ:
      ew = strlen(GACL_TAG_TYPE_USER_OBJ_TEXT);
      break;
    case GACL_TAG_TYPE_USER:
      ew = strlen(GACL_TAG_TYPE_USER_TEXT)+strlen(ep->tag.name);
      break;
    case GACL_TAG_TYPE_GROUP_OBJ:
      ew = strlen(GACL_TAG_TYPE_GROUP_OBJ_TEXT);
      break;
    case GACL_TAG_TYPE_GROUP:
      ew = strlen(GACL_TAG_TYPE_GROUP_TEXT)+strlen(ep->tag.name);
      break;
    case GACL_TAG_TYPE_EVERYONE:
      ew = strlen(GACL_TAG_TYPE_EVERYONE_TEXT);
      break;
    case GACL_TAG_TYPE_MASK:
      ew = strlen(GACL_TAG_TYPE_MASK_TEXT);
      break;
    case GACL_TAG_TYPE_OTHER:
      ew = strlen(GACL_TAG_TYPE_OTHER_TEXT);
      break;
    default:
      return -1;
    }

    if (ew > mw)
      mw = ew;
  }
  return mw;
}


char *
gacl_to_text_np(GACL *ap,
		ssize_t *bsp,
		int flags) {
  char *buf, *bp;
  size_t bufsize = 2048;
  int i, rc;
  GACL_ENTRY *ep;
  int tagwidth = ((flags & GACL_TEXT_STANDARD) ? 18 : _gacl_max_tagwidth(ap)+8);

  
  bp = buf = malloc(bufsize);
  if (!buf)
    return NULL;

  for (i = 0;
       bufsize > 1 && ((rc = gacl_get_entry(ap, i ? GACL_NEXT_ENTRY : GACL_FIRST_ENTRY, &ep)) == 1);
       i++) {
    char es[1024], *cp;
    ssize_t rc, len;
    GACL_TAG_TYPE et;
    
    if (gacl_get_tag_type(ep, &et) < 0)
      goto Fail;
    
    rc = gacl_entry_to_text(ep, es, sizeof(es), flags|GACL_TEXT_STANDARD);
    if (rc < 0)
      goto Fail;

    cp = strchr(es, ':');
    if (cp) {
      len = cp-es;
      if (len > 0 && (et == GACL_TAG_TYPE_USER || et == GACL_TAG_TYPE_GROUP)) {
	cp = strchr(cp+1, ':');
	if (cp)
	  len = cp-es;
      }
    } else
      len = 0;

    if (flags & GACL_TEXT_COMPACT) 
      rc = snprintf(bp, bufsize, "%s%s", (i > 0 ? "," : ""), es);
    else
      if (tagwidth > len)
	rc = snprintf(bp, bufsize, "%*s%s\n", (int) (tagwidth-len), "", es);
      else
	rc = snprintf(bp, bufsize, "%s\n", es);
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
 * We simulate that by stripping the ACL down to the bare owner@/group@/everyone@ entries
 */
int
gacl_delete_file_np(const char *path,
		   GACL_TYPE type) {
  GACL *ap;
  struct stat sb;
  int rc;


  if (vfs_lstat(path, &sb) < 0)
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


  if (vfs_lstat(path, &sb) < 0)
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




int
_gacl_permset_from_text(const char *buf,
			GACL_PERMSET *psp,
			int flags) {
  int i;
  char c;
  GACL_PERMSET nps = 0;


  if (!buf) {
    errno = EINVAL;
    return -1;
  }

  if (!*buf)
    return 0;

  if (strcasecmp(buf, "full_set") == 0 ||
      strcasecmp(buf, "all") == 0)
    nps = GACL_PERM_FULL_SET;
  else if (strcasecmp(buf, "modify_set") == 0 ||
	   strcasecmp(buf, "modify") == 0)
    nps = GACL_PERM_MODIFY_SET;
  else if (strcasecmp(buf, "write_set") == 0 ||
	   strcasecmp(buf, "write") == 0)
    nps = GACL_PERM_WRITE_SET;
  else if (strcasecmp(buf, "read_set") == 0 ||
	   strcasecmp(buf, "read") == 0)
    nps = GACL_PERM_READ_SET;
  else if (strcasecmp(buf, "empty_set") == 0 ||
	   strcasecmp(buf, "empty") == 0 ||
	   strcasecmp(buf, "none") == 0) /* XXX: Remove, but handle the magic 'none' case for edit-access */
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
			GACL_FLAGSET *fsp,
			int flags) {
  int i;
  char c;
  GACL_FLAGSET nfs = 0;


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
		      GACL_ENTRY *ep,
		      int flags) {
  char *np;
  int f_none;

  
  /* 1. Get tag */
  
  if (_gacl_entry_tag_from_text(ep, &cp, flags) < 0)
    return -1;

  /* 2. Get permset */
  np = strchr(cp, ':');
  if (np)
    *np++ = '\0';
  
  f_none = (strcasecmp(cp, "none") == 0);

  if (_gacl_permset_from_text(cp, &ep->perms, flags) < 0)
    return -1;
  cp = np;


  /* 3. Get flagset */
  if (cp && (strcmp(cp, "allow") != 0 &&
	     strcmp(cp, "deny") != 0 &&
	     strcmp(cp, "audit") != 0 &&
	     strcmp(cp, "alarm") != 0)) {
    np = strchr(cp, ':');
    if (np)
      *np++ = '\0';
    /* Parse flags in cp */
    if (_gacl_flagset_from_text(cp, &ep->flags, flags) < 0)
      return -1;
  } else {
    ep->flags = 0;
  }

  cp = np;
  /* 4. Get type (allow, deny, alarm, audit) */
  if (cp) {
    np = strchr(cp, ':');
    if (np) {
      errno = EINVAL;
      return -1;
    }
    if (strcasecmp(cp, "allow") == 0) 
      ep->type = GACL_ENTRY_TYPE_ALLOW;
    else if (strcasecmp(cp, "deny") == 0)
      ep->type = GACL_ENTRY_TYPE_DENY;
    else if (strcasecmp(cp, "audit") == 0)
      ep->type = GACL_ENTRY_TYPE_AUDIT;
    else if (strcasecmp(cp, "alarm") == 0)
      ep->type = GACL_ENTRY_TYPE_ALARM;
    else {
      errno = EINVAL;
      return -1;
    }
  } else {
    if (f_none) {
      ep->perms = GACL_PERM_FULL_SET;
      ep->type = GACL_ENTRY_TYPE_DENY;
    } else 
      ep->type = GACL_ENTRY_TYPE_ALLOW;
  }

  return 0;
}


int
gacl_entry_from_text(char *cp,
		     GACL_ENTRY *ep) {
  return _gacl_entry_from_text(cp, ep, 0);
}


GACL *
gacl_from_text(const char *buf) {
  GACL *ap;
  char *bp, *tbuf, *es;
  const char *cp;
  int ne = 0;

  /* Count the number of potential ACEs */
  for (cp = buf; *cp; ++cp)
    if (*cp == ',')
      ++ne;
  if (*buf)
    ++ne;
  
  bp = tbuf = s_dup(buf);

  ap = gacl_init(ne);
  if (!ap) {
    free(tbuf);
    return NULL;
  }

  while ((es = strsep(&bp, ", \t\n\r")) != NULL) {
    GACL_ENTRY *ep;

    if (gacl_create_entry_np(&ap, &ep, -1) < 0)
      goto Fail;

    if (gacl_entry_from_text(es, ep) < 0)
      goto Fail;
  }

  return ap;

 Fail:
  gacl_free(ap);
  errno = EINVAL;
  return NULL;
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
		 GACL_ENTRY_TYPE type, 
		 GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_valid_file_np(const char *path,
		   GACL_ENTRY_TYPE type,
		   GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_valid_link_np(const char *path,
		   GACL_ENTRY_TYPE type,
		   GACL *ap) {
  errno = ENOSYS;
  return -1;
}

int
gacl_calc_mask(GACL *ap) {
  errno = ENOSYS;
  return -1;
}

