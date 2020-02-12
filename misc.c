/*
 * misc.c - Misc ACL utility functions
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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "strings.h"
#include "misc.h"

#define NEW(vp) ((vp) = malloc(sizeof(*(vp))))

/*
 * Calculate the difference between two struct timespec, returns elapsed time i microseconds.
 * Also returns the elapsed time and a unit as a string.
 */
long
ts_delta(struct timespec *x,
	 const struct timespec *y,
	 long *res,
	 char **unit) {
	struct timespec r;
  
	/* Avoid overflow of r.tv_nsec */
	if (x->tv_nsec < y->tv_nsec) {
	  	x->tv_nsec += 1000000000L;
		x->tv_sec  -= 1;
	}

	r.tv_sec  = x->tv_sec - y->tv_sec;
	r.tv_nsec = x->tv_nsec - y->tv_nsec;
  
	if (unit && res) {
	  	if (r.tv_sec >= 600) {
		  	/* More than 10 minutes -> return minutes */
		  	*unit = "m";
			*res = r.tv_sec / 60;
		} else if (r.tv_sec >= 10) {
		  	/* More than 10 seconds - return seconds */
		  	*unit = "s";
			*res = r.tv_sec;
		} else if (r.tv_sec == 0) {
		  	if (r.tv_nsec <= 10000) {
			  	/* Less than 10us - return nanoseconds */
			  	*unit = "ns";
				*res = r.tv_nsec;
			} else if (r.tv_nsec <= 10000000) {
			  	/* Less than 10ms - return microseconds */
			  	*unit = "µs";
				*res = r.tv_nsec / 1000;
			} else {
			  	*unit = "ms";
				*res = r.tv_nsec / 1000000;
			}
		} else {
		  	*unit = "ms";
			*res = r.tv_sec * 1000 + r.tv_nsec / 1000000;
		}
	}

	/* Microseconds */
	return r.tv_sec * 1000000 + r.tv_nsec / 1000;
}


/* Compare two ACL Entries */
int
cmp_acl_entry(const void *va,
	      const void *vb) {
  acl_entry_type_t aet_a, aet_b;
  acl_entry_t a = * (acl_entry_t *) va;
  acl_entry_t b = * (acl_entry_t *) vb;
  acl_tag_t ta, tb;
  int v;
  acl_flagset_t afs, bfs;
  int inherited_a, inherited_b;
  int inherit_only_a, inherit_only_b;
  void *qa, *qb;
  

  /* Explicit entries goes before inherited ones */
  acl_get_flagset_np(a, &afs);
  acl_get_flagset_np(b, &bfs);
  
  inherit_only_a = acl_get_flag_np(afs, ACL_ENTRY_INHERIT_ONLY);
  inherit_only_b = acl_get_flag_np(bfs, ACL_ENTRY_INHERIT_ONLY);

  /* Ignore this entry if the 'inherit_only' flag is set on one of them */
  if (inherit_only_a || inherit_only_b)
    return 0;
  
  inherited_a = acl_get_flag_np(afs, ACL_ENTRY_INHERITED);
  inherited_b = acl_get_flag_np(bfs, ACL_ENTRY_INHERITED);

  v = inherited_a-inherited_b;
  if (v)
    return v;
  
  /* Deny entries goes before allow ones */
  if (acl_get_entry_type_np(a, &aet_a) < 0)
    return -1;
  
  if (acl_get_entry_type_np(b, &aet_b) < 0)
    return 1;

  v = aet_b - aet_a;
  if (v)
    return v;

  
  /* User entries before group entries before 'other' entries */
  if (acl_get_tag_type(a, &ta) < 0)
    return -1;
  
  if (acl_get_tag_type(b, &tb) < 0)
    return 1;

  if (ta == ACL_USER_OBJ)
    ta = ACL_USER;
  if (tb == ACL_USER_OBJ)
    tb = ACL_USER;
  
  v = ta-tb;
  if (v)
    return v;

  switch (ta) {
  case ACL_USER:
    qa = acl_get_qualifier(a);
    qb = acl_get_qualifier(b);
    
    v = (* (uid_t *) qa)-(* (uid_t *) qb);
    break;
    
  case ACL_GROUP:
    qa = acl_get_qualifier(a);
    qb = acl_get_qualifier(b);
    
    v = (* (gid_t *) qa)-(* (gid_t *) qb);
    break;
  }
  
  if (v)
    return v;
  
  return 0;
}


/* 
 * Compare two ACL Entries - ignore uids & gids
 *
 * CANONICAL SORT ORDER
 *
 * Windows systems wants ACLS to be sorted in a "canonical" order. This is what Microsoft write about it:
 *
 * The preferred order of ACEs in a DACL is called the "canonical" order. For Windows 2000 and Windows
 * Server 2003, the canonical order is the following:
 * 
 *    All explicit ACEs are placed in a group before any inherited ACEs.
 *    Within the group of explicit ACEs, access-denied ACEs are placed before access-allowed ACEs.
 *    Within the inherited group, ACEs that are inherited from the child object's parent come first,
 *    and then ACEs inherited from the grandparent, and so on up the tree of objects. After that,
 *    access-denied ACEs are placed before access-allowed ACEs.
 */
int
cmp_acl_entry_sorted(const void *va,
		     const void *vb) {
  acl_entry_type_t aet_a, aet_b;
  acl_entry_t a = * (acl_entry_t *) va;
  acl_entry_t b = * (acl_entry_t *) vb;
  acl_tag_t ta, tb;
  int v;
  acl_flagset_t afs, bfs;
  int inherit_only_a, inherit_only_b;
  int inherited_a, inherited_b;
  

  /* Explicit entries goes before inherited ones */
  acl_get_flagset_np(a, &afs);
  acl_get_flagset_np(b, &bfs);

  inherit_only_a = acl_get_flag_np(afs, ACL_ENTRY_INHERIT_ONLY);
  inherit_only_b = acl_get_flag_np(bfs, ACL_ENTRY_INHERIT_ONLY);

  /* Ignore this entry if the 'inherit_only' flag is set on one of them */
  if (inherit_only_a || inherit_only_b)
    return 0;
  
  inherited_a = acl_get_flag_np(afs, ACL_ENTRY_INHERITED);
  inherited_b = acl_get_flag_np(bfs, ACL_ENTRY_INHERITED);
  
  v = inherited_a-inherited_b;
  if (v)
    return v;
  
  /* Deny entries goes before allow ones */
  if (acl_get_entry_type_np(a, &aet_a) < 0)
    return -1;
  
  if (acl_get_entry_type_np(b, &aet_b) < 0)
    return 1;

  v = aet_b - aet_a;
  if (v)
    return v;

  
  /* User entries before group entries before 'other' entries */
  if (acl_get_tag_type(a, &ta) < 0)
    return -1;
  
  if (acl_get_tag_type(b, &tb) < 0)
    return 1;

  if (ta == ACL_USER_OBJ)
    ta = ACL_USER;
  if (tb == ACL_USER_OBJ)
    tb = ACL_USER;
  
  v = ta-tb;
  if (v)
    return v;

  return 0;
}


static int
_sort_acl(acl_t a,
	  acl_t *sa,
	  int (*sortfun)(const void *va, const void *vb)) {
  acl_t na;
  acl_entry_t ta, aev[ACL_MAX_ENTRIES], oev[ACL_MAX_ENTRIES];
  int rc, i, aec;
  int id = ACL_FIRST_ENTRY;

  
  for (aec = 0; aec < ACL_MAX_ENTRIES && (rc = acl_get_entry(a, id, &aev[aec])) == 1; ++aec) {
    oev[aec] = aev[aec];
    id = ACL_NEXT_ENTRY;
  }

  if (rc < 0)
    return -1;
  
  mergesort(&aev[0], aec, sizeof(aev[0]), sortfun);
  
  na = acl_init(aec);
  if (!na)
    return -1;

  for (i = 0; i < aec; i++) {
    ta = NULL;
    if (acl_create_entry(&na, &ta) < 0) {
      acl_free(na);
      return -1;
    }

    if (acl_copy_entry(ta, aev[i]) < 0) {
      acl_free(na);
      return -1;
    }
  }

  if (sa)
    *sa = na;
  
  for (i = 0; i < aec && oev[i] == aev[i]; i++)
    ;
  
  if (i >= aec)
    return 0;
  
  return 1;
}


int
sort_acl(acl_t a,
	 acl_t *sa) {
  return _sort_acl(a, sa, cmp_acl_entry);
}


int
is_unsorted_acl(acl_t a) {
  return _sort_acl(a, NULL, cmp_acl_entry_sorted);
}


static struct perm2c {
  int p;
  char c;
  char *s;
} p2c[] = {
	   { ACL_READ_DATA, 'r', "read_data" },
	   { ACL_WRITE_DATA, 'w', "write_data" },
	   { ACL_EXECUTE, 'x', "execute" },
	   { ACL_APPEND_DATA, 'p', "append_data" },
	   { ACL_DELETE_CHILD, 'D', "delete_child" },
	   { ACL_DELETE, 'd', "delete" },
	   { ACL_READ_ATTRIBUTES, 'a', "read_attributes" },
	   { ACL_WRITE_ATTRIBUTES, 'A', "write_attributes" },
	   { ACL_READ_NAMED_ATTRS, 'R', "read_xattrs" },
	   { ACL_WRITE_NAMED_ATTRS, 'W', "write_xattrs" },
	   { ACL_READ_ACL, 'c', "read_acl" }, 
	   { ACL_WRITE_ACL, 'C', "write_acl" },
	   { ACL_WRITE_OWNER, 'o', "write_owner" },
	   { ACL_SYNCHRONIZE, 's', "synchronize" },
	   { 0, 0 }
};

static struct flag2c {
  int f;
  char c;
} f2c[] = {
	   { ACL_ENTRY_FILE_INHERIT, 'f' },
	   { ACL_ENTRY_DIRECTORY_INHERIT, 'd' },
	   { ACL_ENTRY_INHERIT_ONLY, 'i' },
	   { ACL_ENTRY_NO_PROPAGATE_INHERIT, 'n' },
	   { ACL_ENTRY_SUCCESSFUL_ACCESS, 'S' },
	   { ACL_ENTRY_FAILED_ACCESS, 'F' },
	   { ACL_ENTRY_INHERITED, 'I' },
	   { 0, 0 }
};





int
merge_permset(acl_permset_t d,
	      acl_permset_t s) {
  int i, a, rc, ec = 0;

  
  for (i = 0; p2c[i].c; i++) {
    a = acl_get_perm_np(s, p2c[i].p);
    if (a && !acl_get_perm_np(d, p2c[i].p)) {
      rc = acl_add_perm(d, p2c[i].p);
      if (rc < 0)
	return rc;

      ec = 1;
    }
  }

  return ec;
}


int
merge_flagset(acl_flagset_t d,
	      acl_flagset_t s) {
  int i, a, rc, ec = 0;

  
  for (i = 0; f2c[i].c; i++) {
    a = acl_get_flag_np(s, f2c[i].f);
    if (a && !acl_get_flag_np(d, f2c[i].f)) {
      rc = acl_add_flag_np(d, f2c[i].f);
      if (rc < 0)
	return rc;

      ec = 1;
    }
  }

  return ec;
}


int
merge_acl(acl_t *a) {
  acl_t na;
  acl_entry_t ta, aev[ACL_MAX_ENTRIES];
  int i, aec, n = 0, rc = -1;
  int id = ACL_FIRST_ENTRY;


  aec = 0;
  while (aec < ACL_MAX_ENTRIES && (rc = acl_get_entry(*a, id, &ta)) == 1) {
    for (i = 0; i < aec && cmp_acl_entry(&aev[i], &ta) != 0; i++)
      ;
    if (i < aec) {
      /* Match found - merge ACE */
      acl_permset_t ps_a, ps_b;
      acl_flagset_t fs_a, fs_b;
      
      acl_get_permset(aev[i], &ps_a);
      acl_get_permset(ta, &ps_b);
      
      acl_get_flagset_np(aev[i], &fs_a);
      acl_get_flagset_np(ta, &fs_b);
      
      merge_permset(ps_a, ps_b);
      merge_flagset(fs_a, fs_b);
      ++n;
    } else {
      /* No match found - append ACE */
      aev[aec++] = ta;
    }
    id = ACL_NEXT_ENTRY;
  }

  if (rc < 0)
    return rc;

  if (n == 0)
    return 0;
  
  na = acl_init(aec);
  if (!na)
    return -1;

  for (i = 0; i < aec; i++) {
    ta = NULL;
    if (acl_create_entry(&na, &ta) < 0) {
      acl_free(na);
      return -1;
    }

    if (acl_copy_entry(ta, aev[i]) < 0) {
      acl_free(na);
      return -1;
    }
  }

  acl_free(*a);
  *a = na;
  return 1;
}




char *
permset2str(acl_permset_t psp, char *res) {
  static char buf[64];
  int i, a;

  
  if (!res)
    res = buf;
  
  for (i = 0; p2c[i].c; i++) {
    a = acl_get_perm_np(psp, p2c[i].p);
    res[i] = a ? p2c[i].c : '-';
  }
  res[i] = '\0';
  return res;
}

char *
flagset2str(acl_flagset_t fsp, char *res) {
  static char buf[64];
  int i, a;

  
  if (!res)
    res = buf;
  
  for (i = 0; f2c[i].c; i++) {
    a = acl_get_flag_np(fsp, f2c[i].f);
    res[i] = a ? f2c[i].c : '-';
  }
  res[i] = '\0';
  return res;
}


const char *
aet2str(const acl_entry_type_t aet) {
  switch (aet) {
  case 0:
    return "any";
    
  case ACL_ENTRY_TYPE_ALLOW:
    return "allow";

  case ACL_ENTRY_TYPE_DENY:
    return "deny";

  case ACL_ENTRY_TYPE_AUDIT:
    return "audit";

  case ACL_ENTRY_TYPE_ALARM:
    return "alarm";
  }

  return NULL;
}



char *
ace2str(acl_entry_t ae,
	char *rbuf,
	size_t rsize) {
  static char buf[256];
  char *res;
  acl_tag_t at;
  acl_permset_t aps;
  acl_flagset_t afs;
  acl_entry_type_t aet;
  void *qp = NULL;
  struct passwd *pp = NULL;
  struct group *gp = NULL;
  int rc;
  

  if (!rbuf) {
    rbuf = buf;
    rsize = sizeof(buf);
  }

  res = rbuf;
  
  if (acl_get_tag_type(ae, &at) < 0)
    return NULL;

  switch (at) {
  case ACL_USER:
    qp = acl_get_qualifier(ae);
    if (!qp)
      return NULL;

    pp = getpwuid(*(uid_t *) qp);
    if (pp)
      rc = snprintf(res, rsize, "u:%s", pp->pw_name);
    else
      rc = snprintf(res, rsize, "u:%u", * (uid_t *) qp);
    break;
    
  case ACL_GROUP:
    qp = acl_get_qualifier(ae);
    if (!qp)
      return NULL;

    gp = getgrgid(*(gid_t *) qp);
    if (gp)
      rc = snprintf(res, rsize, "g:%s", gp->gr_name);
    else
      rc = snprintf(res, rsize, "g:%u", * (gid_t *) qp);
    break;
    
  case ACL_USER_OBJ:
    rc = snprintf(res, rsize, "%s", "owner@");
    break;
    
  case ACL_GROUP_OBJ:
    rc = snprintf(res, rsize, "%s", "group@");
    break;

  case ACL_MASK:
    rc = snprintf(res, rsize, "%s", "mask@");
    break;

  case ACL_OTHER:
    rc = snprintf(res, rsize, "%s", "other@");
    break;

  case ACL_EVERYONE:
    rc = snprintf(res, rsize, "%s", "everyone@");
    break;

  default:
    errno = EINVAL;
    return NULL;
  }
  
  if (rc < 0)
    return NULL;
  
  if (rc > rsize-1) {
    errno = ENOMEM;
    return NULL;
  }
  
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = ':';
  ++rbuf;
  --rsize;

  if (acl_get_permset(ae, &aps) < 0)
    return NULL;
  
  permset2str(aps, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = ':';
  ++rbuf;
  --rsize;
  
  if (acl_get_flagset_np(ae, &afs) < 0)
    return NULL;
  
  flagset2str(afs, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = ':';
  ++rbuf;
  --rsize;

  acl_get_entry_type_np(ae, &aet);
  strcpy(rbuf, aet2str(aet));
  return res;
}



typedef struct ftdcb {
  char *path;
  struct stat stat;
  size_t base;
  size_t level;
  struct ftdcb *next;
} FTDCB;

typedef struct ftcb {
  FTDCB *head;
  FTDCB **lastp;
} FTCB;


static void
_ftcb_init(FTCB *ftcb) {
  ftcb->head = NULL;
  ftcb->lastp = &ftcb->head;
}

static void
_ftcb_destroy(FTCB *ftcb) {
  FTDCB *ftdcb, *next;

  for (ftdcb = ftcb->head; ftdcb; ftdcb = next) {
    next = ftdcb->next;
    
    free(ftdcb->path);
    free(ftdcb);
  }
}


int
_ft_foreach(const char *path,
	    struct stat *stat,
	    int (*walker)(const char *path,
			  const struct stat *stat,
			  size_t base,
			  size_t level,
			  void *vp),
	    void *vp,
	    size_t curlevel,
	    size_t maxlevel) {
  FTCB ftcb;
  FTDCB *ftdcb;
  DIR *dp;
  struct dirent *dep;
  int rc;
  struct stat sb;
  size_t plen;


  rc = walker(path, stat, 0, curlevel, vp);
  if (rc < 0)
    return rc;

  if (!S_ISDIR(stat->st_mode) || (maxlevel >= 0 && curlevel == maxlevel))
    return 0;

  ++curlevel;
  
  _ftcb_init(&ftcb);
  plen = strlen(path);
  
  dp = opendir(path);
  if (!dp)
    return -1;
  
  while ((dep = readdir(dp)) != NULL) {
    char *fpath;
    
    /* Ignore . and .. */
    if (strcmp(dep->d_name, ".") == 0 ||
	strcmp(dep->d_name, "..") == 0)
      continue;
    
    fpath = s_cat(path, "/", dep->d_name, NULL);
    if (!fpath) {
      rc = -1;
      goto End;
    }

    if (lstat(fpath, &sb) < 0) {
      free(fpath);
      rc = -1;
      goto End;
    }

    /* Add to queue if directory */
    if (S_ISDIR(sb.st_mode)) {
      FTDCB *ftdcb;


      if (NEW(ftdcb) == NULL) {
	rc = -1;
	goto End;
      }
      
      ftdcb->path = fpath;
      ftdcb->base = plen+1;
      ftdcb->stat = sb;
      ftdcb->next = NULL;
      
      *(ftcb.lastp) = ftdcb;
      ftcb.lastp = &ftdcb->next;
    }
    else {
      rc = walker(fpath, &sb, 0, curlevel, vp);
      free(fpath);
      if (rc)
	goto End;
    }
  }

  closedir(dp);
  dp = NULL;
  
  for (ftdcb = ftcb.head; ftdcb; ftdcb = ftdcb->next) {
    rc = _ft_foreach(ftdcb->path, &ftdcb->stat, walker, vp, curlevel, maxlevel);
    if (rc)
      break;
  }

 End:
  if (dp)
    closedir(dp);
  _ftcb_destroy(&ftcb);
  return rc;
}

int
ft_foreach(const char *path,
	    int (*walker)(const char *path,
			  const struct stat *stat,
			  size_t base,
			  size_t level,
			  void *vp),
	    void *vp,
	    size_t maxlevel) {
  struct stat stat;

  
  if (lstat(path, &stat) < 0)
    return -1;
  
  return _ft_foreach(path, &stat, walker, vp, 0, maxlevel);
}


int
str2style(const char *str,
	  ACL_STYLE *sp) {
  if (!str || !*str)
    return 0;
  
  if (strcasecmp(str, "default") == 0)
    *sp = ACL_STYLE_DEFAULT;
  else if (strcasecmp(str, "brief") == 0)
    *sp = ACL_STYLE_BRIEF;
  else if (strcasecmp(str, "verbose") == 0)
    *sp = ACL_STYLE_VERBOSE;
  else if (strcasecmp(str, "csv") == 0)
    *sp = ACL_STYLE_CSV;
  else if (strcasecmp(str, "solaris") == 0)
    *sp = ACL_STYLE_SOLARIS;
  else if (strcasecmp(str, "primos") == 0)
    *sp = ACL_STYLE_PRIMOS;
  else
    return -1;

  return 1;
}

const char *
style2str(ACL_STYLE s) {
  switch (s) {
  case ACL_STYLE_DEFAULT:
    return "Default";
  case ACL_STYLE_BRIEF:
    return "Brief";
  case ACL_STYLE_VERBOSE:
    return "Verbose";
  case ACL_STYLE_CSV:
    return "CSV";
  case ACL_STYLE_SOLARIS:
    return "Solaris";
  case ACL_STYLE_PRIMOS:
    return "PRIMOS";
  }

  return NULL;
}
