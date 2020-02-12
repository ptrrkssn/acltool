/*
 * aclcmds.c - ACL commands
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <ftw.h>

#include "acltool.h"
#include "misc.h"
#include "commands.h"
#include "aclcmds.h"


static CONFIG *w_cfgp = NULL;
static size_t w_c = 0;

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
  case S_IFWHT:
    buf[0] = 'w';
    break;
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
  buf[9] = (m & S_IXOTH ? (m & S_ISTXT ? 't' : 'x') : (m & S_ISTXT ? 'T' : '-'));

  buf[10] = '\0';
  return buf;
}


int
print_acl(FILE *fp,
	  acl_t a,
	  const char *path,
	  const struct stat *sp,
	  CONFIG *cfgp) {
  acl_entry_t ae;
  int i, is_trivial, d;
  char *as, *cp;
  char acebuf[2048], ubuf[64], gbuf[64], tbuf[80], *us, *gs;
  struct passwd *pp = NULL;
  struct group *gp = NULL;
  struct tm *tp;
  

  if (strncmp(path, "./", 2) == 0)
    path += 2;
  
  switch (cfgp->f_style) {
  case ACL_STYLE_DEFAULT:
    pp = NULL;
    gp = NULL;
    if (sp) {
      pp = getpwuid(sp->st_uid);
      gp = getgrgid(sp->st_gid);
    }

    if (!pp) {
      snprintf(ubuf, sizeof(ubuf), "%u", sp->st_uid);
      us = ubuf;
    } else
      us = pp->pw_name;
    
    if (!gp) {
      snprintf(gbuf, sizeof(gbuf), "%u", sp->st_gid);
      gs = gbuf;
    } else
      gs = gp->gr_name;
    
    as = acl_to_text_np(a, NULL, (w_cfgp->f_verbose ? ACL_TEXT_VERBOSE|ACL_TEXT_APPEND_ID : 0));
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL\n", argv0, path);
      return 1;
    }

    if (w_c)
      putc('\n', fp);
    
    fprintf(fp, "# file: %s\n", path);
    fprintf(fp, "# owner: %s\n", us);
    fprintf(fp, "# group: %s\n", gs);
    fputs(as, fp);
    acl_free(as);
    break;
    
  case ACL_STYLE_CSV:
    /* One-liner, CSV-style */

    pp = NULL;
    gp = NULL;
    if (sp) {
      pp = getpwuid(sp->st_uid);
      gp = getgrgid(sp->st_gid);
    }

    fprintf(fp, "%s;", path);
    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      if (i)
	putc(',', fp);
      ace2str(ae, acebuf, sizeof(acebuf));
      fprintf(fp, "%s", acebuf);
    }
    if (pp)
      fprintf(fp, ";%s", pp->pw_name);
    else
      fprintf(fp, ";%d", sp->st_uid);
    if (gp)
      fprintf(fp, ";%s", gp->gr_name);
    else
      fprintf(fp, ";%d", sp->st_gid);
    
    putc('\n', fp);
    break;

  case ACL_STYLE_BRIEF:
    /* One-liner */

    fprintf(fp, "%-22s", path);
    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      ace2str(ae, acebuf, sizeof(acebuf));
      cp = strchr(acebuf, ':');
      if (cp-acebuf == 1)
	cp = strchr(acebuf+2, ':');
      d = 10-(cp-acebuf);
      fprintf(fp, " %*s%s", d, "", acebuf);
    }
    putc('\n', fp);
    break;

  case ACL_STYLE_VERBOSE:
    pp = NULL;
    gp = NULL;
    if (sp) {
      pp = getpwuid(sp->st_uid);
      gp = getgrgid(sp->st_gid);
    }
    
    if (w_c)
      putc('\n', fp);
    
    fprintf(fp, "# file: %s\n", path);
    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      char *cp;
      int len;
      
      ace2str(ae, acebuf, sizeof(acebuf));

      cp = strchr(acebuf, ':');
      len = cp - acebuf;
      fprintf(fp, "%*s%s", (18-len), "", acebuf);
      if (strncmp(acebuf, "owner@", len) == 0) {
	if (pp)
	  fprintf(fp, "\t# %s", pp->pw_name);
	else
	  fprintf(fp, "\t# %d", sp->st_uid);
      }
      if (strncmp(acebuf, "group@", len) == 0) {
	if (gp)
	  fprintf(fp, "\t# %s", gp->gr_name);
	else
	  fprintf(fp, "\t# %d", sp->st_gid);
      }
      putc('\n', fp);
    }
    break;
    
  case ACL_STYLE_SOLARIS:
    pp = NULL;
    gp = NULL;
    if (sp) {
      pp = getpwuid(sp->st_uid);
      gp = getgrgid(sp->st_gid);
    }

    if (!pp) {
      snprintf(ubuf, sizeof(ubuf), "%u", sp->st_uid);
      us = ubuf;
    } else
      us = pp->pw_name;
    
    if (!gp) {
      snprintf(gbuf, sizeof(gbuf), "%u", sp->st_gid);
      gs = gbuf;
    } else
      gs = gp->gr_name;

    tp = localtime(&sp->st_mtime);
    strftime(tbuf, sizeof(tbuf), "%c", tp);

    is_trivial = 0;
    acl_is_trivial_np(a, &is_trivial);
    
    if (w_c)
      putc('\n', fp);
    
    printf("%s%s %2d %8s %8s %8ld %16s %s\n",
	   mode2str(sp->st_mode), is_trivial ? " " : "+",
	   sp->st_nlink,
	   us, gs,
	   sp->st_size,
	   tbuf, path);
	   
    as = acl_to_text_np(a, NULL, (w_cfgp->f_verbose ? ACL_TEXT_VERBOSE|ACL_TEXT_APPEND_ID : 0));
    if (!as) {
      fprintf(stderr, "%s: Error: %s: Unable to display ACL\n", argv0, path);
      return 1;
    }

    fputs(as, fp);
    acl_free(as);
    break;

  case ACL_STYLE_PRIMOS:
    pp = NULL;
    gp = NULL;
    if (sp) {
      pp = getpwuid(sp->st_uid);
      gp = getgrgid(sp->st_gid);
    }
    
    if (w_c)
      putc('\n', fp);
    
    printf("ACL protecting \"%s\":\n", path);
    
    for (i = 0; acl_get_entry(a, i == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; i++) {
      char *perms, *flags, *type;
      
      ace2str(ae, acebuf, sizeof(acebuf));

      perms = strchr(acebuf, ':');
      *perms++ = '\0';
      
      flags = strchr(perms, ':');
      *flags++ = '\0';
      
      type  = strchr(flags, ':');
      *type++ = '\0';

      fprintf(fp, "\t%-15s\t%-15s\t%-15s\t%-6s", acebuf, perms, flags, type);
      if (strcmp(acebuf, "owner@") == 0) {
	if (pp)
	  fprintf(fp, "\t# %s", pp->pw_name);
	else
	  fprintf(fp, "\t# %d", sp->st_uid);
      }
      if (strcmp(acebuf, "group@") == 0) {
	if (gp)
	  fprintf(fp, "\t# %s", gp->gr_name);
	else
	  fprintf(fp, "\t# %d", sp->st_gid);
      }
      putc('\n', fp);
    }
    break;
    
  default:
    return -1;
  }
  
  return 0;
}


static int
walker_strip(const char *path,
	     const struct stat *sp,
	     size_t base,
	     size_t level,
	     void *vp) {
  int rc;
  acl_t ap, na;
  int tf;
  
  
  if (S_ISLNK(sp->st_mode))
    ap = acl_get_link_np(path, ACL_TYPE_NFS4);
  else
    ap = acl_get_file(path, ACL_TYPE_NFS4);
  
  if (!ap) {
    fprintf(stderr, "%s: Error: %s: Getting ACL\n", argv0, path);
    return 1;
  }

  tf = 0;
  if (acl_is_trivial_np(ap, &tf) < 0) {
    acl_free(ap);
    return -1;
  }

  if (tf) {
    acl_free(ap);
    return 0;
  }
  
  na = acl_strip_np(ap, 0);
  acl_free(ap);
  
  rc = 0;
  if (!w_cfgp->f_noupdate) {
    if (S_ISLNK(sp->st_mode))
      rc = acl_set_link_np(path, ACL_TYPE_NFS4, na);
    else
      rc = acl_set_file(path, ACL_TYPE_NFS4, na);
  }
  
  acl_free(na);
  if (rc < 0) {
    fprintf(stderr, "%s: Error: %s: Setting ACL: %s\n", argv0, path, strerror(errno));
    return 1;
  }

  if (w_cfgp->f_verbose)
    printf("%s: ACL Stripped%s\n", path, (w_cfgp->f_noupdate ? " (NOT)" : ""));
  
  return 0;
}


static int
walker_sort(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  int rc;
  acl_t ap, na;

  
  if (S_ISLNK(sp->st_mode))
    ap = acl_get_link_np(path, ACL_TYPE_NFS4);
  else
    ap = acl_get_file(path, ACL_TYPE_NFS4);
  
  if (!ap) {
    fprintf(stderr, "%s: Error: %s: Getting ACL\n", argv0, path);
    return 1;
  }

  rc = sort_acl(ap, &na);
  acl_free(ap);

  if (rc < 0)
    return rc;

  if (rc == 1) {
    rc = 0;
    if (!w_cfgp->f_noupdate) {
      if (S_ISLNK(sp->st_mode))
	rc = acl_set_link_np(path, ACL_TYPE_NFS4, na);
      else
	rc = acl_set_file(path, ACL_TYPE_NFS4, na);
    }
    acl_free(na);
    if (rc < 0) {
      fprintf(stderr, "%s: Error: %s: Setting ACL: %s\n", argv0, path, strerror(errno));
      return 1;
    }

    if (w_cfgp->f_verbose)
      printf("%s: ACL Sorted%s\n", path, (w_cfgp->f_noupdate ? " (NOT)" : ""));
  }

  return 0;
}

static int
walker_copy(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  int rc;
  acl_t ap = (acl_t) vp;

  
  if (!w_cfgp->f_noupdate) {
    if (S_ISLNK(sp->st_mode))
      rc = acl_set_link_np(path, ACL_TYPE_NFS4, ap);
    else
      rc = acl_set_file(path, ACL_TYPE_NFS4, ap);
    if (rc < 0) {
      fprintf(stderr, "%s: Error: %s: Setting ACL: %s\n", argv0, path, strerror(errno));
      return 1;
    }
  }

  if (w_cfgp->f_verbose)
    printf("%s: ACL Copied%s\n", path, (w_cfgp->f_noupdate ? " (NOT)" : ""));
  
  return 0;
}

static int
walker_print(const char *path,
	     const struct stat *sp,
	     size_t base,
	     size_t level,
	     void *vp) {
  acl_t ap;
  FILE *fp;


  fp = stdout;
  
  if (S_ISLNK(sp->st_mode))
    ap = acl_get_link_np(path, ACL_TYPE_NFS4);
  else
    ap = acl_get_file(path, ACL_TYPE_NFS4);
  
  if (!ap) {
    fprintf(stderr, "%s: Error: %s: Unable to read ACL\n", argv0, path);
    return 1;
  }
  
  print_acl(fp, ap, path, sp, w_cfgp);
  acl_free(ap);
  
  ++w_c;
  
  return 0;
}



int
_aclcmd_foreach(int argc,
		char **argv,
		CONFIG *cfgp,
		int (*handler)(const char *path,
			       const struct stat *sp,
			       size_t base,
			       size_t level,
			       void *vp),
		void *vp) {
  int i, rc = 0;
  

  w_cfgp = cfgp;
  
  for (i = 1; rc == 0 && i < argc; i++) {
    rc = ft_foreach(argv[i], handler, vp,
		    cfgp->f_recurse ? -1 : cfgp->max_depth);
    if (rc)
      break;
  }
  
  return rc;
}

int
aclcmd_list(int argc,
	    char **argv,
	    void *vp) {	       
  return _aclcmd_foreach(argc, argv, (CONFIG *) vp, walker_print, NULL);
}



int
aclcmd_copy(int argc,
	    char **argv,
	    void *vp) {	       
  int i, rc;
  acl_t ap;
  struct stat s0;

  
  i = 1;
  if (lstat(argv[i], &s0) != 0) {
    fprintf(stderr, "%s: Error: %s: Accessing: %s\n", argv[0], argv[1], strerror(errno));
    return 1;
  }

  if (S_ISLNK(s0.st_mode))
    ap = acl_get_link_np(argv[i], ACL_TYPE_NFS4);
  else
    ap = acl_get_file(argv[i], ACL_TYPE_NFS4);
  if (!ap) {
    fprintf(stderr, "%s: Error: %s: Getting ACL: %s\n", argv[0], argv[1], strerror(errno));
    return 1;
  }

  --argc;
  ++argv;

  rc = _aclcmd_foreach(argc, argv, (CONFIG *) vp, walker_copy, (void *) ap);
  
  acl_free(ap);
  return rc;
}

int
aclcmd_sort(int argc,
	    char **argv,
	    void *vp) {	       
  return _aclcmd_foreach(argc, argv, (CONFIG *) vp, walker_sort, NULL);
}


int
aclcmd_strip(int argc,
	     char **argv,
	     void *vp) {	       
  return _aclcmd_foreach(argc, argv, (CONFIG *) vp, walker_strip, NULL);
}

int
aclcmd_set(int argc,
	   char **argv,
	   void *vp) {	       
  fprintf(stderr, "%s: Error: %s: Not yet implemented\n", argv0, argv[0]);
  return 1;
}

int
aclcmd_grep(int argc,
	    char **argv,	
	    void *vp) {	       
  fprintf(stderr, "%s: Error: %s: Not yet implemented\n", argv0, argv[0]);
  return 1;
}

int
aclcmd_edit(int argc,
	    char **argv,
	    void *vp) {	       
  fprintf(stderr, "%s: Error: %s: Not yet implemented\n", argv0, argv[0]);
  return 1;
}

int
aclcmd_inherit(int argc,
	       char **argv,
	       void *vp) {	       
  fprintf(stderr, "%s: Error: %s: Not yet implemented\n", argv0, argv[0]);
  return 1;
}

int
aclcmd_check(int argc,
	     char **argv,
	     void *vp) {
  fprintf(stderr, "%s: Error: %s: Not yet implemented\n", argv0, argv[0]);
  return 1;
}


COMMAND acl_commands[] = {
  { "list-access", 	"<path>+",	aclcmd_list,	"List ACL(s)" },
  { "strip-access",     "<path>+",	aclcmd_strip,	"Strip ACL(s)" },
  { "sort-access",      "<path>+",	aclcmd_sort,	"Sort ACL(s)" },
  { "copy-access",      "<src> <dst>+",	aclcmd_copy,	"Copy ACL(s)" },
#if 0
  { "inherit-access",   "<path>+",	aclcmd_inherit,	"Propage ACL(s) inheritance" },
  { "set-access",  	"<path>+",	aclcmd_set,	"Set ACL(s)" },
  { "edit-access",      "<path>+",	aclcmd_edit,	"Edit ACL(s)" },
  { "grep-access",      "<path>+",	aclcmd_grep,	"Search ACL(s)" },
  { "check-access",     "<path>+",	aclcmd_check,	"Sanity-check ACL(s)" },
#endif
  { NULL,		NULL,		NULL,		NULL },
};
