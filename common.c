/*
 * common.c - Common functions
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
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <ftw.h>
#include <limits.h>

#include "acltool.h"
#include "common.h"


acl_t 
get_acl(const char *path, 
	const struct stat *sp) {
  acl_t ap;
  struct stat sbuf;


  if (!sp) {
    if (lstat(path, &sbuf) < 0)
      return NULL;
    
    sp = &sbuf;
  }

  if (S_ISLNK(sp->st_mode))
    ap = acl_get_link_np(path, ACL_TYPE_NFS4);
  else
    ap = acl_get_file(path, ACL_TYPE_NFS4);
  if (!ap) {
    error(1, errno, "Getting ACL");
    return NULL;
  }

  return ap;
}


int
print_ace(acl_t ap,
	  int p,
	  int flags) {
  acl_entry_t ae;
  char buf[1024];

  
  if (_gacl_get_entry(ap, p, &ae) < 0)
    return -1;
  
  if (acl_entry_to_text(ae, buf, sizeof(buf), flags) < 0)
    return -1;
  
  puts(buf);
  return 0;
}


int
set_acl(const char *path,
	const struct stat *sp,
	acl_t nap,
	acl_t oap) {
  int rc, s_errno;
  acl_t ap = nap;


  if (config.f_sort) {
    acl_t sap = acl_sort(ap);
    
    if (!sap) {
      error(1, errno, "%s: Sorting ACL", path);
      return -1;
    }
    ap = sap;
  }

  if (config.f_merge) {
    acl_t map = acl_merge(ap);
    
    if (!map) {
      s_errno = errno;
      if (ap != nap)
	acl_free(ap);
      error(1, s_errno, "%s: Merging ACL", path);
      return -1;
    }
    if (ap != nap)
      acl_free(ap);
    ap = map;
  }

  if (config.f_print > 1)
    print_acl(stdout, ap, path, sp);
  
  /* Skip set operation if old and new acl is the same (and force flag not in use) */
  if (oap && acl_match(ap, oap) == 1 && !config.f_force) {
    if (ap != nap)
      acl_free(ap);
    return 0;
  }

  rc = 0;
  if (!config.f_noupdate) {
    if (S_ISLNK(sp->st_mode))
      rc = acl_set_link_np(path, ACL_TYPE_NFS4, ap);
    else
      rc = acl_set_file(path, ACL_TYPE_NFS4, ap);
  }

  if (rc < 0) {
    s_errno = errno;
    if (ap != nap)
      acl_free(ap);
    error(1, s_errno, "%s: Setting ACL", path);
    return rc;
  }

  if (config.f_print == 1)
    print_acl(stdout, ap, path, sp);
  
  if (config.f_verbose)
    printf("%s: ACL Updated%s\n", path, (config.f_noupdate ? " (NOT)" : ""));
  
  if (ap != nap)
    acl_free(ap);

  return 1;
}


#define UPDATE(v,t) if (f_add) {*v |= t;} else { *v &= ~t; }

int
str2filetype(const char *str,
	     mode_t *f_filetype) {
  int f_add = 1;

  
  *f_filetype = 0;
  
  for (; *str; ++str)
    switch (*str) {
    case '+':
      f_add = 1;
      break;
      
    case '-':
      f_add = 0;
      break;
      
    case 'f':
      UPDATE(f_filetype, S_IFREG);
      break;
      
    case 'd':
      UPDATE(f_filetype, S_IFDIR);
      break;
      
    case 'b':
      UPDATE(f_filetype, S_IFBLK);
      break;
      
    case 'c':
      UPDATE(f_filetype, S_IFCHR);
      break;
      
    case 'l':
      UPDATE(f_filetype, S_IFLNK);
      break;
      
    case 'p':
      UPDATE(f_filetype, S_IFIFO);
      break;
      
    case 's':
      UPDATE(f_filetype, S_IFSOCK);
      break;
      
#ifdef S_IFWHT
    case 'w':
      UPDATE(f_filetype, S_IFWHT);
      break;
#endif
    default:
      return -1;
    }

  return (*f_filetype ? 1 : 0);
}


static int
primos_print_perms(FILE *fp,
		   const char *s) {
  int c;
  int ns = 0;
  
  
  while ((c = *s++) != '\0') {
    if (c == '-')
      ++ns;
    else
      putc(c, fp);
  }

  while (ns-- > 0)
    putc(' ', fp);
  return 0;
}


static int
primos_print_flags(FILE *fp,
		   const char *s) {
  int c;
  int ns = 0;
  int np = 0;

  while ((c = *s++) != '\0') {
    if (c == '-')
      ++ns;
    else {
      if (np++ == 0)
	putc('(', fp);
      putc(c, fp);
    }
  }

  if (np == 0)
    ns += 2;
  else
    putc(')', fp);
  while (ns-- > 0)
    putc(' ', fp);
  return 0;
}


int
print_acl(FILE *fp,
	  acl_t a,
	  const char *path,
	  const struct stat *sp) {
  acl_entry_t ae;
  int i, is_trivial, len;
  uid_t *idp;
  char *as;
  char acebuf[2048], ubuf[64], gbuf[64], tbuf[80], *us, *gs;
  struct passwd *pp = NULL;
  struct group *gp = NULL;
  struct tm *tp;
  

  if (strncmp(path, "./", 2) == 0)
    path += 2;

  us = gs = NULL;
  pp = NULL;
  gp = NULL;
  if (sp) {
    pp = getpwuid(sp->st_uid);
    gp = getgrgid(sp->st_gid);
  }
  
  if (!pp) {
    snprintf(ubuf, sizeof(ubuf), "%u", sp->st_uid);
    us = s_dup(ubuf);
  } else
    us = s_dup(pp->pw_name);
  
  if (!gp) {
    snprintf(gbuf, sizeof(gbuf), "%u", sp->st_gid);
    gs = s_dup(gbuf);
  } else
    gs = s_dup(gp->gr_name);
  
  switch (config.f_style) {
  case ACL_STYLE_DEFAULT:
    as = acl_to_text_np(a, NULL, (config.f_verbose ? ACL_TEXT_VERBOSE|ACL_TEXT_APPEND_ID : 0));
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL\n", argv0, path);
      return 1;
    }

    fprintf(fp, "# file: %s\n", path);
    
    if (config.f_verbose)
      fprintf(fp, "# owner: %s (%d)\n", us, sp->st_uid);
    else
      fprintf(fp, "# owner: %s\n", us);
    
    if (config.f_verbose)
      fprintf(fp, "# group: %s (%d)\n", gs, sp->st_gid);
    else
      fprintf(fp, "# group: %s\n", gs);
    
    if (config.f_verbose)
      fprintf(fp, "# type: %s\n", mode2typestr(sp->st_mode));
    if (config.f_verbose > 1) {
      fprintf(fp, "# size: %lu\n", sp->st_size);
      fprintf(fp, "# modified: %s", ctime(&sp->st_mtime));
      fprintf(fp, "# changed:  %s", ctime(&sp->st_ctime));
      fprintf(fp, "# accessed: %s", ctime(&sp->st_atime));
#ifdef st_birthtime
      fprintf(fp, "# created:  %s", ctime(&sp->st_birthtime));
#endif
    }

    fputs(as, fp);
    acl_free(as);
    break;

  case ACL_STYLE_STANDARD:
    as = acl_to_text_np(a, NULL, ACL_TEXT_STANDARD_NP|(config.f_verbose ? ACL_TEXT_VERBOSE|ACL_TEXT_APPEND_ID : 0));
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL\n", argv0, path);
      return 1;
    }

    fprintf(fp, "# file: %s\n", path);
    fprintf(fp, "# owner: %s\n", us);
    fprintf(fp, "# group: %s\n", gs);
    fputs(as, fp);
    acl_free(as);
    break;
    
  case ACL_STYLE_CSV:
    /* One-liner, CSV-style */

    as = acl_to_text_np(a, NULL, ACL_TEXT_COMPACT_NP);
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL: %s\n", argv0, path, strerror(errno));
      return 1;
    }
    fprintf(fp, "%s;%s;%d;%d;%s;%s\n", path, as, sp->st_uid, sp->st_gid, us ? us : "-", gs ? gs : "-");
    acl_free(as);
    break;

  case ACL_STYLE_BRIEF:
    /* One-liner */

    as = acl_to_text_np(a, NULL, ACL_TEXT_COMPACT_NP);
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL: %s\n", argv0, path, strerror(errno));
      return 1;
    }
    
    fprintf(fp, "%-24s  %s\n", path, as);
    acl_free(as);
    break;

  case ACL_STYLE_VERBOSE:
    fprintf(fp, "# file: %s\n", path);
    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      char *cp;
      int len;
      acl_tag_t tt;

      acl_get_tag_type(ae, &tt);
      ace2str(ae, acebuf, sizeof(acebuf));

      cp = strchr(acebuf, ':');
      if (cp) {
	len = cp-acebuf;
	if (len > 0 && (tt == ACL_USER || tt == ACL_GROUP)) {
	  cp = strchr(cp+1, ':');
	  if (cp)
	    len = cp-acebuf;
	}
      } else
	len = 0;

      fprintf(fp, "%*s%s", (18-len), "", acebuf);
      switch (tt) {
      case ACL_USER_OBJ:
	if (us) {
	  if (config.f_verbose)
	    fprintf(fp, "\t# %s (%d)", us, sp->st_uid);
	  else
	    fprintf(fp, "\t# %s", us);
	} else
	  fprintf(fp, "\t# (%d)", sp->st_uid);
	break;

      case ACL_GROUP_OBJ:
	if (gs) {
	  if (config.f_verbose)
	    fprintf(fp, "\t# %s (%d)", gs, sp->st_gid);
	  else
	    fprintf(fp, "\t# %s", gs);
	} else
	  fprintf(fp, "\t# (%d)", sp->st_gid);
	break;

      case ACL_USER:
      case ACL_GROUP:
	if (config.f_verbose) {
	  idp = (uid_t *) acl_get_qualifier(ae);
	  if (idp)
	    fprintf(fp, "\t# (%d)", *idp);
	}
	break;

      default:
	break;
      }
      putc('\n', fp);
    }
    break;
    
  case ACL_STYLE_SOLARIS:
    tp = localtime(&sp->st_mtime);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %R", tp);

    is_trivial = 0;
    acl_is_trivial_np(a, &is_trivial);
    
    printf("%s%s %2lu %8s %8s %8ld %16s %s\n",
	   mode2str(sp->st_mode), is_trivial ? " " : "+",
	   (unsigned long int) sp->st_nlink,
	   us, gs,
	   sp->st_size,
	   tbuf, path);
	   
    as = acl_to_text_np(a, NULL, (config.f_verbose ? ACL_TEXT_VERBOSE|ACL_TEXT_APPEND_ID : 0));
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL\n", argv0, path);
      return 1;
    }

    fputs(as, fp);
    acl_free(as);
    break;

  case ACL_STYLE_PRIMOS:
    printf("ACL protecting \"%s\":\n", path);
    
    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      char *perms, *flags, *type;
      acl_tag_t tt;

      acl_get_tag_type(ae, &tt);
      ace2str(ae, acebuf, sizeof(acebuf));

      perms = strchr(acebuf, ':');
      if (!perms) {
	fprintf(stderr, "%s: Error: %s: Unable to display ACL\n", argv0, path);
	return 1;
      }
      
      if (tt == ACL_USER || tt == ACL_GROUP)
	perms = strchr(++perms, ':');
      *perms++ = '\0';

      flags = strchr(perms, ':');
      *flags++ = '\0';
      
      type  = strchr(flags, ':');
      *type++ = '\0';

      fprintf(fp, "\t%30s:  ", acebuf);
      primos_print_perms(fp, perms);
      fprintf(fp, "  ");
      primos_print_flags(fp, flags);
      if (strcmp(type, "allow") != 0)
	fprintf(fp, "  %-5s", type);
      switch (tt) {
      case ACL_USER_OBJ:
	if (us) {
	  if (config.f_verbose)
	    fprintf(fp, "  # %s (%d)", us, sp->st_uid);
	  else 
	    fprintf(fp, "  # %s", us);
	} else
	  fprintf(fp, "  # (%d)", sp->st_uid);
	break;

      case ACL_GROUP_OBJ:
	if (gs) {
	  if (config.f_verbose)
	    fprintf(fp, "  # %s (%d)", gs, sp->st_gid);
	  else
	    fprintf(fp, "  # %s", gs);
	} else
	  fprintf(fp, "  # (%d)", sp->st_gid);
	break;

      case ACL_USER:
      case ACL_GROUP:
	if (config.f_verbose) {
	  idp = (uid_t *) acl_get_qualifier(ae);
	  if (idp)
	    fprintf(fp, "  # (%d)", *idp);
	}
	break;

      default:
	break;
      }

      putc('\n', fp);
    }
    break;
    
  case ACL_STYLE_SAMBA:
    fprintf(fp, "FILENAME:%s\n", path);
    fprintf(fp, "REVISION:1\n");
    fprintf(fp, "CONTROL:SR|DP\n");

    if (pp)
      fprintf(fp, "OWNER:%s\n", us);
    else
      fprintf(fp, "OWNER:%d\n", sp->st_uid);

    if (gp)
      fprintf(fp, "GROUP:%s\n", gs);
    else
      fprintf(fp, "GROUP:%d\n", sp->st_gid);

    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      char *cp;
      ace2str_samba(ae, acebuf, sizeof(acebuf), sp);

      cp = strrchr(acebuf, '\t');
      if (*cp) {
	*cp++ = '\0';
	fprintf(fp, "%-60s\t# %s\n", acebuf, cp);
      } else
	fprintf(fp, "%s\n", acebuf);
    }
    break;
    
  case ACL_STYLE_ICACLS:
    len = strlen(path);

    fprintf(fp, "%s", path);

    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      ace2str_icacls(ae, acebuf, sizeof(acebuf), sp);
      fprintf(fp, "%*s %s\n", i ? len : 0, "", acebuf);
    }
    break;
    
  default:
    return -1;
  }
  
  free(us);
  free(gs);
  return 0;
}


int
str2style(const char *str,
	  ACL_STYLE *sp) {
  if (!str || !*str)
    return 0;
  
  if (strcasecmp(str, "default") == 0)
    *sp = ACL_STYLE_DEFAULT;
  else if (strcasecmp(str, "standard") == 0)
    *sp = ACL_STYLE_STANDARD;
  else if (strcasecmp(str, "brief") == 0)
    *sp = ACL_STYLE_BRIEF;
  else if (strcasecmp(str, "verbose") == 0)
    *sp = ACL_STYLE_VERBOSE;
  else if (strcasecmp(str, "csv") == 0)
    *sp = ACL_STYLE_CSV;
  else if (strcasecmp(str, "samba") == 0)
    *sp = ACL_STYLE_SAMBA;
  else if (strcasecmp(str, "icacls") == 0)
    *sp = ACL_STYLE_ICACLS;
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
  case ACL_STYLE_STANDARD:
    return "Standard";
  case ACL_STYLE_BRIEF:
    return "Brief";
  case ACL_STYLE_VERBOSE:
    return "Verbose";
  case ACL_STYLE_CSV:
    return "CSV";
  case ACL_STYLE_SAMBA:
    return "Samba";
  case ACL_STYLE_ICACLS:
    return "ICACLS";
  case ACL_STYLE_SOLARIS:
    return "Solaris";
  case ACL_STYLE_PRIMOS:
    return "PRIMOS";
  }

  return NULL;
}

char *
mode2typestr(mode_t m) {
  switch (m & S_IFMT) {
  case S_IFIFO:
    return config.f_verbose ? "fifo" : "p";
  case S_IFCHR:
    return config.f_verbose ? "char-device" : "c";
  case S_IFBLK:
    return config.f_verbose ? "block-device" : "b";
  case S_IFDIR:
    return config.f_verbose ? "directory" : "d";
  case S_IFREG:
    return config.f_verbose ? "file" : "-";
  case S_IFLNK:
    return config.f_verbose ? "link" : "l";
  case S_IFSOCK:
    return config.f_verbose ? "socket" : "s";
#ifdef S_IFWHT
  case S_IFWHT:
    return config.f_verbose ? "whiteout" : "w";
#endif
  default:
    return config.f_verbose ? "unknown" : "?";
  }
}

char *
mode2str(mode_t m) {
  static char buf[11];

  switch (m & S_IFMT) {
  case S_IFIFO:
    buf[0] = 'p';
    break;
  case S_IFCHR:
    buf[0] = 'c';
    break;
  case S_IFDIR:
    buf[0] = 'd';
    break;
  case S_IFBLK:
    buf[0] = 'b';
    break;
  case S_IFREG:
    buf[0] = '-';
    break;
  case S_IFLNK:
    buf[0] = 'l';
    break;
  case S_IFSOCK:
    buf[0] = 's';
    break;
#ifdef S_IFWHT
  case S_IFWHT:
    buf[0] = 'w';
    break;
#endif
  default:
    buf[0] = '?';
  }
  
  buf[1] = (m & S_IRUSR ? 'r' : '-');
  buf[2] = (m & S_IWUSR ? 'w' : '-');
  buf[3] = (m & S_IXUSR ? (m & S_ISUID ? 's' : 'x') : (m & S_ISUID ? 'S' : '-'));

  buf[4] = (m & S_IRGRP ? 'r' : '-');
  buf[5] = (m & S_IWGRP ? 'w' : '-');
  buf[6] = (m & S_IXGRP ? (m & S_ISGID ? 's' : 'x') : (m & S_ISGID ? 'S' : '-'));

  buf[7] = (m & S_IROTH ? 'r' : '-');
  buf[8] = (m & S_IWOTH ? 'w' : '-');
  buf[9] = (m & S_IXOTH ? (m & S_ISVTX ? 't' : 'x') : (m & S_ISVTX ? 'T' : '-'));

  buf[10] = '\0';
  return buf;
}

int
aclcmd_foreach(int argc,
	       char **argv,
	       int (*handler)(const char *path,
			      const struct stat *sp,
			      size_t base,
			      size_t level,
			      void *vp),
	       void *vp) {
  int i, rc = 0;
  

  for (i = 0; rc == 0 && i < argc; i++) {
    rc = ft_foreach(argv[i], handler, vp,
		    config.f_recurse ? -1 : config.max_depth, config.f_filetype);
    if (rc) {
      if (rc < 0) {
	fprintf(stderr, "%s: Error: %s: Accessing object: %s\n", 
		argv0, argv[i], strerror(errno));
	rc = 1;
      }
      break;
    }
  }

  return rc;
}
