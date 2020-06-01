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

#include "config.h"

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
#include <termios.h>

#include "acltool.h"

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


static struct gace_perm2c {
  int p;
  char c;
  char *s;
} p2c[] = {
		{ GACL_PERM_READ_DATA, 'r', "read_data" },
		{ GACL_PERM_WRITE_DATA, 'w', "write_data" },
		{ GACL_PERM_EXECUTE, 'x', "execute" },
		{ GACL_PERM_APPEND_DATA, 'p', "append_data" },
		{ GACL_PERM_DELETE, 'd', "delete" },
		{ GACL_PERM_DELETE_CHILD, 'D', "delete_child" },
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
} f2c[] = {
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


static struct perm2c_windows {
  int p;
  char *c;
  char *s;
} p2c_windows[] = {
	   { GACL_PERM_READ_DATA,         "R",   "read_data"        },
	   { GACL_PERM_WRITE_DATA,        "W",   "write_data"       },
	   { GACL_PERM_EXECUTE,           "X",   "execute"          },
	   { GACL_PERM_DELETE,            "D",   "delete"           },
	   { GACL_PERM_WRITE_ACL,         "P",   "write_acl"        },
	   { GACL_PERM_WRITE_OWNER,       "O",   "write_owner"      },
	   { GACL_PERM_READ_ATTRIBUTES,   "RA",  "read_attributes"  },
	   { GACL_PERM_WRITE_ATTRIBUTES,  "WA",  "write_attributes" },
	   { GACL_PERM_DELETE_CHILD,      "DC",  "delete_child"     },
	   { GACL_PERM_APPEND_DATA,       "AD",  "append_data"      },
	   { GACL_PERM_READ_NAMED_ATTRS,  "REA", "read_xattrs"      },
	   { GACL_PERM_WRITE_NAMED_ATTRS, "WEA", "write_xattrs"     },
	   { GACL_PERM_SYNCHRONIZE,       "S",   "synchronize"      },
	   { GACL_PERM_READ_ACL,          "AS",  "read_acl"         }, 
	   { 0, NULL, NULL }
};


static struct flag2str_windows {
  int f;
  char *s;
} f2c_windows[] = {
	   { GACL_FLAG_FILE_INHERIT,         "OI" },
	   { GACL_FLAG_DIRECTORY_INHERIT,    "CI" },
	   { GACL_FLAG_INHERITED,            "I"  },
	   { GACL_FLAG_NO_PROPAGATE_INHERIT, "NP" },
	   { GACL_FLAG_INHERIT_ONLY,         "IO" },
	   { GACL_FLAG_SUCCESSFUL_ACCESS,    "S"  },
	   { GACL_FLAG_FAILED_ACCESS,        "F"  },
	   { 0, NULL }
};








char *
permset2str(gacl_permset_t psp, char *res) {
  static char buf[64];
  int i, a;

  
  if (!res)
    res = buf;
  
  for (i = 0; p2c[i].c; i++) {
    a = gacl_get_perm_np(psp, p2c[i].p);
    res[i] = a ? p2c[i].c : '-';
  }
  res[i] = '\0';
  return res;
}

char *
permset2str_samba(gacl_permset_t psp,
		  char *res) {
  static char buf[64];
  int i, a, n;

  
  if (!res)
    res = buf;

  res[0] = '\0';
  n = 0;
  for (i = 0; p2c_windows[i].c; i++) {
    a = gacl_get_perm_np(psp, p2c_windows[i].p);
    if (a) {
      if (n++)
	strcat(res, "|");
      strcat(res, p2c_windows[i].c);
    }
  }
  return res;
}


char *
permset2str_icacls(gacl_permset_t psp,
		   char *res) {
  static char buf[64];
  int i, a, n;

  
  if (!res)
    res = buf;

  res[0] = '\0';
  n = 0;
  strcat(res, "(");
  for (i = 0; p2c_windows[i].c; i++) {
    a = gacl_get_perm_np(psp, p2c_windows[i].p);
    if (a) {
      if (n++)
	strcat(res, ",");
      strcat(res, p2c_windows[i].c);
    }
  }
  strcat(res, ")");
  return res;
}

char *
flagset2str(gacl_flagset_t fsp, char *res) {
  static char buf[64];
  int i, a;

  
  if (!res)
    res = buf;
  
  for (i = 0; f2c[i].c; i++) {
    a = gacl_get_flag_np(fsp, f2c[i].f);
    res[i] = a ? f2c[i].c : '-';
  }
  res[i] = '\0';
  return res;
}

char *
flagset2str_samba(gacl_flagset_t fsp,
		  char *res) {
  static char buf[64];
  int i, a, n;

  
  if (!res)
    res = buf;

  res[0] = '\0';

  n = 0;
  for (i = 0; f2c_windows[i].s; i++) {
    a = gacl_get_flag_np(fsp, f2c_windows[i].f);
    if (a) {
      if (n++)
	strcat(res, "|");
      strcat(res, f2c_windows[i].s);
    }
  }

  return res;
}

char *
flagset2str_icacls(gacl_flagset_t fsp,
		   char *res) {
  static char buf[64];
  int i, a;

  
  if (!res)
    res = buf;

  res[0] = '\0';

  for (i = 0; f2c_windows[i].s; i++) {
    a = gacl_get_flag_np(fsp, f2c_windows[i].f);
    if (a) {
      strcat(res, "(");
      strcat(res, f2c_windows[i].s);
      strcat(res, ")");
    }
  }

  return res;
}


const char *
aet2str(gacl_entry_type_t aet) {
  switch (aet) {
  case GACL_ENTRY_TYPE_UNDEFINED:
    return NULL;
    
  case GACL_ENTRY_TYPE_ALLOW:
    return "allow";

  case GACL_ENTRY_TYPE_DENY:
    return "deny";

  case GACL_ENTRY_TYPE_AUDIT:
    return "audit";

  case GACL_ENTRY_TYPE_ALARM:
    return "alarm";
  }

  return NULL;
}



char *
ace2str_samba(gacl_entry_t ae,
	      char *rbuf,
	      size_t rsize,
	      const struct stat *sp) {
  static char buf[256];
  char *res;
  gacl_tag_t at;
  gacl_permset_t aps;
  gacl_flagset_t afs;
  gacl_entry_type_t aet;
  void *qp = NULL;
  struct passwd *pp = NULL;
  struct group *gp = NULL;
  int rc;
  

  if (!rbuf) {
    rbuf = buf;
    rsize = sizeof(buf);
  }

  res = rbuf;
  
  if (gacl_get_tag_type(ae, &at) < 0)
    return NULL;

  switch (at) {
  case GACL_TAG_TYPE_USER:
    qp = gacl_get_qualifier(ae);
    if (!qp)
      return NULL;

    pp = getpwuid(*(uid_t *) qp);
    if (pp) {
      gp = getgrnam(pp->pw_name);
      rc = snprintf(res, rsize, "ACL:%s%s:", pp->pw_name, gp ? "(user)" : "");
    } else {
      gp = getgrgid(*(gid_t *) qp);
      rc = snprintf(res, rsize, "ACL:%u%s:", * (uid_t *) qp, gp ? "(user)" : "");
    }
    gacl_free(qp);
    break;
    
  case GACL_TAG_TYPE_GROUP:
    qp = gacl_get_qualifier(ae);
    if (!qp)
      return NULL;

    gp = getgrgid(*(gid_t *) qp);
    if (gp) { 
      pp = getpwnam(gp->gr_name);
      rc = snprintf(res, rsize, "ACL:%s%s:", gp->gr_name, pp ? "(group)" : "");
    } else {
      pp = getpwuid(*(uid_t *) qp);
      rc = snprintf(res, rsize, "ACL:%u%s:", * (gid_t *) qp, pp ? "(group)" : "");
    }
    gacl_free(qp);
    break;
    
  case GACL_TAG_TYPE_USER_OBJ:
    pp = getpwuid(sp->st_uid);
    if (pp)
      rc = snprintf(res, rsize, "ACL:%s:", pp->pw_name);
    else
      rc = snprintf(res, rsize, "ACL:%u:", sp->st_uid);
    break;
    
  case GACL_TAG_TYPE_GROUP_OBJ:
    gp = getgrgid(sp->st_gid);
    if (gp) {
      if (getpwnam(gp->gr_name))
	rc = snprintf(res, rsize, "ACL:GROUP=%s:", gp->gr_name);
      else
	rc = snprintf(res, rsize, "ACL:%s:", gp->gr_name);
    } else
      rc = snprintf(res, rsize, "ACL:GID=%u:", sp->st_gid);
    break;

  case GACL_TAG_TYPE_MASK:
    rc = snprintf(res, rsize, "ACL:%s:", "mask@");
    break;

  case GACL_TAG_TYPE_OTHER:
    rc = snprintf(res, rsize, "ACL:%s:", "Everyone");
    break;

  case GACL_TAG_TYPE_EVERYONE:
    rc = snprintf(res, rsize, "ACL:%s:", "Everyone");
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

  
  gacl_get_entry_type_np(ae, &aet);
  
  switch (aet) {
  case GACL_ENTRY_TYPE_UNDEFINED:
    return NULL;
  case GACL_ENTRY_TYPE_ALLOW:
    rc = snprintf(rbuf, rsize, "ALLOWED/");
    break;
  case GACL_ENTRY_TYPE_DENY:
    rc = snprintf(rbuf, rsize, "ALLOWED/");
    break;
  case GACL_ENTRY_TYPE_AUDIT:
    rc = snprintf(rbuf, rsize, "AUDIT/");
    break;
  case GACL_ENTRY_TYPE_ALARM:
    rc = snprintf(rbuf, rsize, "ALARM/");
    break;
  }

  rbuf += rc;
  rsize -= rc;
  

  if (gacl_get_flagset_np(ae, &afs) < 0)
    return NULL;
  
  flagset2str_samba(afs, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = '/';
  ++rbuf;
  --rsize;

  if (gacl_get_permset(ae, &aps) < 0)
    return NULL;
  
  permset2str_samba(aps, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = '\t';
  ++rbuf;
  --rsize;
  
  permset2str(aps, rbuf);
  
  return res;
}


char *
ace2str_icacls(gacl_entry_t ae,
	      char *rbuf,
	      size_t rsize,
	      const struct stat *sp) {
  static char buf[256];
  char *res;
  gacl_tag_t at;
  gacl_permset_t aps;
  gacl_flagset_t afs;
#if 0
  gacl_entry_type_t aet;
#endif
  void *qp = NULL;
  struct passwd *pp = NULL;
  struct group *gp = NULL;
  int rc;
  

  if (!rbuf) {
    rbuf = buf;
    rsize = sizeof(buf);
  }

  res = rbuf;
  
  if (gacl_get_tag_type(ae, &at) < 0)
    return NULL;

  switch (at) {
  case GACL_TAG_TYPE_USER:
    qp = gacl_get_qualifier(ae);
    if (!qp)
      return NULL;

    pp = getpwuid(*(uid_t *) qp);
    if (pp)
      rc = snprintf(res, rsize, "%s:", pp->pw_name);
    else
      rc = snprintf(res, rsize, "%u:", * (uid_t *) qp);
    gacl_free(qp);
    break;
    
  case GACL_TAG_TYPE_GROUP:
    qp = gacl_get_qualifier(ae);
    if (!qp)
      return NULL;

    gp = getgrgid(*(gid_t *) qp);
    if (gp) {
      if (getpwnam(gp->gr_name))
	rc = snprintf(res, rsize, "GROUP=%s:", gp->gr_name);
      else
	rc = snprintf(res, rsize, "%s:", gp->gr_name);
    } else
      rc = snprintf(res, rsize, "GID=%u:", * (gid_t *) qp);
    gacl_free(qp);
    break;
    
  case GACL_TAG_TYPE_USER_OBJ:
    pp = getpwuid(sp->st_uid);
    if (pp)
      rc = snprintf(res, rsize, "%s:", pp->pw_name);
    else
      rc = snprintf(res, rsize, "%u:", sp->st_uid);
    break;
    
  case GACL_TAG_TYPE_GROUP_OBJ:
    gp = getgrgid(sp->st_gid);
    if (gp) {
      if (getpwnam(gp->gr_name))
	rc = snprintf(res, rsize, "GROUP=%s:", gp->gr_name);
      else
	rc = snprintf(res, rsize, "%s:", gp->gr_name);
    } else
      rc = snprintf(res, rsize, "GID=%u:", sp->st_gid);
    break;

  case GACL_TAG_TYPE_MASK:
    rc = snprintf(res, rsize, "%s:", "mask@");
    break;

  case GACL_TAG_TYPE_OTHER:
    rc = snprintf(res, rsize, "%s:", "Everyone");
    break;

  case GACL_TAG_TYPE_EVERYONE:
    rc = snprintf(res, rsize, "%s:", "Everyone");
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


#if 0
  /* XXX: How to show DENY ACEs? */
  
  gacl_get_entry_type_np(ae, &aet);
  
  switch (aet) {
  case GACL_ENTRY_TYPE_ALLOW:
    break;
  case GACL_ENTRY_TYPE_DENY:
    rc = snprintf(rbuf, rsize, "DENIED/");
    break;
  case GACL_ENTRY_TYPE_AUDIT:
    rc = snprintf(rbuf, rsize, "AUDIT/");
    break;
  case GACL_ENTRY_TYPE_ALARM:
    rc = snprintf(rbuf, rsize, "ALARM/");
    break;
  }

  rbuf += rc;
  rsize -= rc;
#endif

  if (gacl_get_flagset_np(ae, &afs) < 0)
    return NULL;
  
  flagset2str_icacls(afs, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  
  if (gacl_get_permset(ae, &aps) < 0)
    return NULL;
  
  permset2str_icacls(aps, rbuf);

  return res;
}



char *
ace2str(gacl_entry_t ae,
	char *rbuf,
	size_t rsize) {
  static char buf[256];
  char *res;
  gacl_tag_t at;
  gacl_permset_t aps;
  gacl_flagset_t afs;
  gacl_entry_type_t aet;
  void *qp = NULL;
  struct passwd *pp = NULL;
  struct group *gp = NULL;
  int rc;
  

  if (!rbuf) {
    rbuf = buf;
    rsize = sizeof(buf);
  }

  res = rbuf;
  
  if (gacl_get_tag_type(ae, &at) < 0)
    return NULL;

  switch (at) {
  case GACL_TAG_TYPE_USER:
    qp = gacl_get_qualifier(ae);
    if (!qp)
      return NULL;

    pp = getpwuid(*(uid_t *) qp);
    if (pp)
      rc = snprintf(res, rsize, "u:%s", pp->pw_name);
    else
      rc = snprintf(res, rsize, "u:%u", * (uid_t *) qp);
    gacl_free(qp);
    break;
    
  case GACL_TAG_TYPE_GROUP:
    qp = gacl_get_qualifier(ae);
    if (!qp)
      return NULL;

    gp = getgrgid(*(gid_t *) qp);
    if (gp)
      rc = snprintf(res, rsize, "g:%s", gp->gr_name);
    else
      rc = snprintf(res, rsize, "g:%u", * (gid_t *) qp);
    gacl_free(qp);
    break;
    
  case GACL_TAG_TYPE_USER_OBJ:
    rc = snprintf(res, rsize, "%s", "owner@");
    break;
    
  case GACL_TAG_TYPE_GROUP_OBJ:
    rc = snprintf(res, rsize, "%s", "group@");
    break;

  case GACL_TAG_TYPE_MASK:
    rc = snprintf(res, rsize, "%s", "mask@");
    break;

  case GACL_TAG_TYPE_OTHER:
    rc = snprintf(res, rsize, "%s", "other@");
    break;

  case GACL_TAG_TYPE_EVERYONE:
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

  if (gacl_get_permset(ae, &aps) < 0)
    return NULL;
  
  permset2str(aps, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = ':';
  ++rbuf;
  --rsize;
  
  if (gacl_get_flagset_np(ae, &afs) < 0)
    return NULL;
  
  flagset2str(afs, rbuf);
  rc = strlen(rbuf);
  rbuf += rc;
  rsize -= rc;

  rbuf[0] = ':';
  ++rbuf;
  --rsize;

  gacl_get_entry_type_np(ae, &aet);
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
	    size_t maxlevel,
	    mode_t filetypes) {
  FTCB ftcb;
  FTDCB *ftdcb;
  DIR *dp;
  struct dirent *dep;
  int rc;
  struct stat sb;
  size_t plen;

  
  if (!filetypes || (stat->st_mode & filetypes))
    rc = walker(path, stat, 0, curlevel, vp);
  else
    rc = 0;
  if (rc < 0)
    return rc;

  if (!S_ISDIR(stat->st_mode) || (maxlevel >= 0 && curlevel == maxlevel))
    return 0;

  ++curlevel;
  
  _ftcb_init(&ftcb);
  plen = strlen(path);
  
  dp = vfs_opendir(path);
  if (!dp)
    return -1;
  
  while ((dep = vfs_readdir(dp)) != NULL) {
    char *fpath;

    /* Ignore . and .. */
    if (strcmp(dep->d_name, ".") == 0 ||
	strcmp(dep->d_name, "..") == 0)
      continue;
    
    fpath = s_dupcat(path, "/", dep->d_name, NULL);
    if (!fpath) {
      rc = -1;
      goto End;
    }

    if (vfs_lstat(fpath, &sb) < 0) {
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
      if (!filetypes || (sb.st_mode & filetypes))
	rc = walker(fpath, &sb, 0, curlevel, vp);
      else
	rc = 0;
      free(fpath);
      if (rc)
	goto End;
    }
  }

  vfs_closedir(dp);
  dp = NULL;
  
  for (ftdcb = ftcb.head; ftdcb; ftdcb = ftdcb->next) {
    rc = _ft_foreach(ftdcb->path, &ftdcb->stat, walker, vp, curlevel, maxlevel, filetypes);
    if (rc)
      break;
  }

 End:
  if (dp)
    vfs_closedir(dp);
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
	   size_t maxlevel,
	   mode_t filetypes) {
  struct stat stat;


  if (vfs_lstat(path, &stat) < 0)
    return -1;
  
  return _ft_foreach(path, &stat, walker, vp, 0, maxlevel, filetypes);
}


int
prompt_user(char *buf,
	    size_t bufsize,
	    int echo,
	    const char *prompt,
	    ...) {
  struct termios oflags, nflags;
  int i;
  char *res;
  va_list ap;
  

  va_start(ap, prompt);
  i = vfprintf(stderr, prompt, ap);
  va_end(ap);
  if (i < 0)
    return -1;
  
  if (!echo) {
    if (tcgetattr(fileno(stdin), &oflags) < 0)
      return -1;
    
    nflags = oflags;
    nflags.c_lflag &= ~ECHO;
    nflags.c_lflag |= ECHONL;
    
    if (tcsetattr(fileno(stdin), TCSANOW, &nflags) < 0) {
      return -1;
    }
  }
  
  res = fgets(buf, bufsize, stdin);

  if (res) {
    /* Remove trailing newline(s) */
    i = strlen(buf)-1;
    while (i >= 0 && (buf[i] == '\n' || buf[i] == '\r'))
      --i;
    buf[i+1] = '\0';
  }
  
  if (!echo) {
    /* restore terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &oflags) <0)
      return -1;
  }
  
  return res ? i : 0;
}
