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

#include "config.h"

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
#include "range.h"


static size_t w_c = 0;


int
_acl_filter_file(gacl_t ap) {
  gacl_entry_t ae;
  int i;
  

  for (i = 0; gacl_get_entry(ap, i == 0 ? GACL_FIRST_ENTRY : GACL_NEXT_ENTRY, &ae) == 1; i++) {
    gacl_flagset_t fs;
    int fi;

    if (gacl_get_flagset_np(ae, &fs) < 0)
      return -1;

    fi = gacl_get_flag_np(fs, GACL_FLAG_INHERITED);

    /* Remove all flags except for the INHERITED one */
    gacl_clear_flags_np(fs);
    if (fi)
      gacl_add_flag_np(fs, GACL_FLAG_INHERITED);

    if (gacl_set_flagset_np(ae, fs) < 0)
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
  gacl_t ap, na;
  int tf;
  

  rc = get_acl(path, sp, &ap);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", path);
  if (rc == 0)
    return 0;
  
  tf = 0;
  if (gacl_is_trivial_np(ap, &tf) < 0) {
    int s_errno = errno;
    
    gacl_free(ap);
    return error(0, s_errno, "%s: Internal Error (gacl_is_trivial_np)", path);
  }

  if (tf) {
    gacl_free(ap);
    return 0;
  }
  
  na = gacl_strip_np(ap, 0);

  rc = set_acl(path, sp, na, ap);

  gacl_free(na);
  gacl_free(ap);

  if (rc < 0)
    return 1;

  return 0;
}

static int
walker_delete(const char *path,
	      const struct stat *sp,
	      size_t base,
	      size_t level,
	      void *vp) {
  int rc;
  
  
  if (S_ISLNK(sp->st_mode)) {
    rc = gacl_delete_link_np(path, GACL_TYPE_NFS4);
    if (errno == ENOTSUP) /* Solaris does not support ACLs on symbolic links */
      return 0;
  } else
    rc = gacl_delete_file_np(path, GACL_TYPE_NFS4);
  
  if (rc < 0)
    return error(1, errno, "%s: Deleting ACL", path);

  if (config.f_verbose)
    printf("%s: ACL Deleted%s\n", path, (config.f_noupdate ? " (NOT)" : ""));
  
  return 0;
}


static int
walker_sort(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  int rc;
  gacl_t ap, na;


  rc = get_acl(path, sp, &ap);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", path);
  if (rc == 0)
    return 0;
  
  na = gacl_sort(ap);
  if (!na)
    return error(1, errno, "%s: Sorting ACL", path);

  rc = set_acl(path, sp, na, ap);

  gacl_free(na);
  gacl_free(ap);

  if (rc < 0)
    return 1;
  
  return 0;
}

static int
walker_touch(const char *path,
	     const struct stat *sp,
	     size_t base,
	     size_t level,
	     void *vp) {
  int rc;
  gacl_t ap;


  rc = get_acl(path, sp, &ap);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", path);
  if (rc == 0)
    return 0;

  rc = set_acl(path, sp, ap, ap);
  gacl_free(ap);

  if (rc < 0)
    return 1;

  return 0;
}



typedef struct {
  gacl_t da;
  gacl_t fa;
} DACL;


static int
walker_set(const char *path,
	   const struct stat *sp,
	   size_t base,
	   size_t level,
	   void *vp) {
  int rc;
  DACL *a = (DACL *) vp;

  
  if (S_ISDIR(sp->st_mode))
    rc = set_acl(path, sp, a->da, NULL);
  else
    rc = set_acl(path, sp, a->fa, NULL);
  
  if (rc < 0) {
    if (config.f_ignore)
      return 0;
    
    return 1;
  }

  return 0;
}




/* XXX: Change to use ACECR */
static int
walker_find(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  gacl_t ap, map = (gacl_t) vp;
  int i, j, rc;
  gacl_entry_t ae, mae;


  rc = get_acl(path, sp, &ap);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", path);
  if (rc == 0)
    return 0;

  for (i = 0; gacl_get_entry(ap, i == 0 ? GACL_FIRST_ENTRY : GACL_NEXT_ENTRY, &ae) == 1; i++) {
    for (j = 0; gacl_get_entry(map, j == 0 ? GACL_FIRST_ENTRY : GACL_NEXT_ENTRY, &mae) == 1; j++) {
      int rc;
      
      rc = gacl_entry_match(ae, mae);
      if (rc < 0)
	return -1;

      if (rc > 0) {
	/* Found a match */
	if (config.f_verbose)
	  print_acl(stdout, ap, path, sp, 0);
	else
	  puts(path);
	
	w_c++;
	return 0;
      }
    }
  }

  return 0;
}

static int
walker_print(const char *path,
	     const struct stat *sp,
	     size_t base,
	     size_t level,
	     void *vp) {
  gacl_t ap = NULL;
  FILE *fp;
  int *np = (int *) vp;
  int rc;
  
  
  fp = stdout;

  rc = get_acl(path, sp, &ap);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", path);

  ++*np;
  print_acl(fp, ap, path, sp, np ? *np : 0);

  if (ap)
    gacl_free(ap);
  
  ++w_c;
  
  return 0;
}



int
list_cmd(int argc,
	    char **argv) {
  int n = 0;
  return aclcmd_foreach(argc-1, argv+1, walker_print, &n);
}

int
get_cmd(int argc,
	char **argv) {
  int i, rc;
  
  
  for (i = 1; i < argc; i++) {
    gacl_t ap;
    char *pp, *as, *ns;

    pp = strchr(argv[i], '=');
    if (!pp)
      return error(1, 0, "%s: Missing required '=' character", argv[i]);

    *pp++ = '\0';

    rc = get_acl(pp, NULL, &ap);
    if (rc <= 0)
      return error(1, errno, "%s: Getting ACL", pp);

    as = gacl_to_text_np(ap, NULL, GACL_TEXT_COMPACT);
    if (!as) {
      int ec = errno;
      
      gacl_free(ap);
      return error(1, ec, "%s: Converting ACL to text", pp);
    }

    ns = s_dupcat(argv[i], "=", as, NULL);
    if (!ns) {
      int ec = errno;
      
      gacl_free(ap);
      return error(1, ec, "%s: Memory allocation");
    }
    
    gacl_free(as);
    
    if (putenv(ns) < 0) {
      int ec = errno;

      free(ns);
      gacl_free(ap);
      return error(1, ec, "%s: Putenv: %s\n", argv[i]);
    }
    
    free(ns);
    gacl_free(ap);
  }

  return 0;
}



int
copy_cmd(int argc,
	 char **argv) {
  int rc;
#if 0
  struct stat s0;
#endif
  DACL a;


#if 0
  if (vfs_lstat(argv[1], &s0) != 0)
    return error(1, errno, "%s: Accessing", argv[1]);
#endif
  
  rc = get_acl(argv[1], NULL, &a.da);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", argv[1]);
  if (rc == 0)
    return 0;
  
  a.fa = gacl_dup(a.da);
  if (!a.fa) {
    int ec = errno;
    
    gacl_free(a.da);
    return error(1, ec, "%s: Internal Fault (gacl_dup)", argv[1]);
  }
 
  _acl_filter_file(a.fa);

  rc = aclcmd_foreach(argc-2, argv+2, walker_set, (void *) &a);
  
  gacl_free(a.da);
  gacl_free(a.fa);
  return rc;
}

int
sort_cmd(int argc,
	 char **argv) {
  return aclcmd_foreach(argc-1, argv+1, walker_sort, NULL);
}

int
touch_cmd(int argc,
	 char **argv) {
  return aclcmd_foreach(argc-1, argv+1, walker_touch, NULL);
}


int
strip_cmd(int argc,
	  char **argv) {
  return aclcmd_foreach(argc-1, argv+1, walker_strip, NULL);
}

int
delete_cmd(int argc,
	   char **argv) {
  return aclcmd_foreach(argc-1, argv+1, walker_delete, NULL);
}


int
set_cmd(int argc,
	char **argv) {
  int rc;
  DACL a;


  if (argc < 2)
    return error(1, 0, "Missing required arguments (<acl> <path>)");

  a.da = gacl_from_text(argv[1]);
  if (!a.da)
    return error(1, errno, "%s: Invalid ACL", argv[1]);

  a.fa = gacl_dup(a.da);
  if (!a.fa) {
    int ec = errno;
    
    gacl_free(a.da);
    return error(1, ec, "%s: Invalid ACL", argv[1]);
  }
  
  _acl_filter_file(a.fa);

  rc = aclcmd_foreach(argc-2, argv+2, walker_set, (void *) &a);

  gacl_free(a.da);
  gacl_free(a.fa);

  return rc;
}


#define MAXRENAMELIST 1024

typedef struct {
  int c;
  struct {
    GACL_TAG old;
    GACL_TAG new;
  } v[MAXRENAMELIST];
} RENAMELIST;


static int
walker_rename(const char *path,
	      const struct stat *sp,
	      size_t base,
	      size_t level,
	      void *vp) {
  int rc, i, j;
  RENAMELIST *r = (RENAMELIST *) vp;
  gacl_t ap = NULL;
  gacl_entry_t ae = NULL;
  int f_updated = 0;


  rc = get_acl(path, sp, &ap);
  if (rc < 0)
    return error(1, errno, "%s: Getting ACL", path);
  if (rc == 0)
    return 0;

  for (i = 0; gacl_get_entry(ap, i == 0 ? GACL_FIRST_ENTRY : GACL_NEXT_ENTRY, &ae) == 1; i++) {
    for (j = 0; j < r->c; j++) {
      if (_gacl_tag_compare(&ae->tag, &r->v[j].old) == 0) {
	rc = _gacl_set_tag(ae, &r->v[j].new);
	if (rc < 0)
	  return error(1, errno, "%s: Updating ACL", path);
	f_updated = 1;
      }
    }
  }
  
  if (f_updated) {
    rc = set_acl(path, sp, ap, NULL);
    if (rc < 0)
      return error(1, errno, "%s: Setting ACL", path);
  }

  gacl_free(ap);
  return 0;
}


int
str2renamelist(char *str,
	       RENAMELIST *r) {
  int rc;
  

  if (!str) {
    errno = EINVAL;
    return -1;
  }
     
  r->c = 0;

  while (*str) {
    rc = _gacl_tag_from_text(&r->v[r->c].new, &str, GACL_TEXT_RELAXED);
    if (rc < 0)
      return -1;
    if (*str == '=')
      ++str;
    else if (*str) {
      errno = EINVAL;
      return -1;
    }
    
    rc = _gacl_tag_from_text(&r->v[r->c].old, &str, GACL_TEXT_RELAXED);
    if (rc < 0)
      return -1;
    if (*str == ',')
      ++str;
    else if (*str) {
      errno = EINVAL;
      return -1;
    }
    
    r->c++;
  }

  return 0;
}


int
rename_cmd(int argc,
	   char **argv) {
  int rc;
  RENAMELIST r;

  
  if (argc < 2)
    return error(1, 0, "Missing required arguments (<acl> <path>)");
  
  if (str2renamelist(argv[1], &r) < 0)
    return error(1, 0, "%s: Invalid renamelist", argv[1]);

  rc = aclcmd_foreach(argc-2, argv+2, walker_rename, (void *) &r);

  return rc;
}


int
find_cmd(int argc,
	 char **argv) {
  gacl_t ap;


  if (argc < 2)
    return error(1, 0, "Missing required arguments (<acl> <path>)");

  ap = gacl_from_text(argv[1]);

  return aclcmd_foreach(argc-2, argv+2, walker_find, (void *) ap);
}




static int
walker_inherit(const char *path,
	   const struct stat *sp,
	   size_t base,
	   size_t level,
	   void *vp) {
  DACL *a = (DACL *) vp;
  gacl_t ap = NULL;


  if (!a) {
    errno = EINVAL;
    return -1;
  }
  
  if (!a->da) {
    gacl_entry_t ep;
    int p, rc;
    
    rc = get_acl(path, sp, &ap);
    if (rc < 0)
      return error(1, errno, "%s: Getting ACL", path);
    if (rc == 0)
      return 0;

    a->da = gacl_dup(ap);
    if (!a->da)
      goto Fail;
    
    for (p = GACL_FIRST_ENTRY; gacl_get_entry(a->da, p, &ep) == 1; p = GACL_NEXT_ENTRY) {
      gacl_flagset_t fs;

      if (gacl_get_flagset_np(ep, &fs) < 0)
	goto Fail;

      if (S_ISDIR(sp->st_mode)) {
	gacl_add_flag_np(fs, GACL_FLAG_FILE_INHERIT);
	gacl_add_flag_np(fs, GACL_FLAG_DIRECTORY_INHERIT);
      }
      gacl_delete_flag_np(fs, GACL_FLAG_NO_PROPAGATE_INHERIT);
      
      if (gacl_set_flagset_np(ep, fs) < 0)
	goto Fail;
    }

    /* Update the ACL with FILE & DIR INHERIT (if a directory) */
    if (set_acl(path, sp, a->da, ap) < 0)
      return error(1, errno, "%s: Setting ACL", path);
    
    for (p = GACL_FIRST_ENTRY; gacl_get_entry(a->da, p, &ep) == 1; p = GACL_NEXT_ENTRY) {
      gacl_flagset_t fs;

      if (gacl_get_flagset_np(ep, &fs) < 0)
	goto Fail;

      gacl_delete_flag_np(fs, GACL_FLAG_INHERIT_ONLY);
      gacl_add_flag_np(fs, GACL_FLAG_INHERITED);
      
      if (gacl_set_flagset_np(ep, fs) < 0)
	goto Fail;
    }

    a->fa = gacl_dup(a->da);
    if (!a->fa)
      goto Fail;
    
    if (_acl_filter_file(a->fa) < 0)
      goto Fail;
    
    return 0;
  } else {
    int rc;
    gacl_t oap;
    
    rc = get_acl(path, sp, &oap);
    if (rc < 0)
      return error(1, errno, "%s: Getting ACL", path);
    if (rc == 0)
      return 0;
    
    if (S_ISDIR(sp->st_mode))
      rc = set_acl(path, sp, a->da, oap);
    else
      rc = set_acl(path, sp, a->fa, oap);
    if (rc < 0)
      return error(1, errno, "%s: Setting ACL", path);
    
    gacl_free(oap);
    return 0;
  }

  return 0;
  
 Fail:
  if (a && a->da)
    gacl_free(a->da);
  if (ap)
    gacl_free(ap);
  return -1;
}


int
inherit_cmd(int argc,
	    char **argv) {
  int i, rc = 0;

  
  w_c = 0;

  for (i = 1; i < argc; i++) {
    DACL a;
    
    a.da = NULL;
    a.fa = NULL;

    rc = ft_foreach(argv[i], walker_inherit, (void *) &a,
		    config.f_recurse ? -1 : config.max_depth, config.f_filetype);
    
    if (a.da)
      gacl_free(a.da);
    if (a.fa)
      gacl_free(a.fa);
  }

  return rc;
}


static int
walker_check(const char *path,
	     const struct stat *sp,
	     size_t base,
	     size_t level,
	     void *vp) {
  errno = ENOSYS;
  return -1;
}


int
check_cmd(int argc,
	  char **argv) {
  return aclcmd_foreach(argc-1, argv+1, walker_check, NULL);
}

extern COMMAND edit_command;


COMMAND list_command =
  { "list-access", 	list_cmd,	NULL, "<path>+",		"List ACL(s)" };

COMMAND set_command =
  { "set-access",  	set_cmd,	NULL, "<acl> <path>+",		"Set ACL(s)" };

COMMAND touch_command =
  { "touch-access",     touch_cmd,	NULL, "<path>+",		"Touch/update ACL(s)" };

COMMAND get_command =
  { "get-access", 	get_cmd,	NULL, "<var>=<path>+",		"Get ACL into variable" };


#if 0
COMMAND strip_command =
  { "strip-access",     strip_cmd,	NULL, "<path>+",		"Strip ACL(s)" };

COMMAND sort_command =
  { "sort-access",      sort_cmd,	NULL, "<path>+",		"Sort ACL(s)" };
#endif

COMMAND copy_command =
  { "copy-access",     copy_cmd,	NULL, "<src> <dst>+",		"Copy ACL(s)" };

COMMAND delete_command =
  { "delete-access",    delete_cmd,	NULL, "<path>+",		"Delete ACL(s)" };

COMMAND find_command =
  { "find-access",      find_cmd,	NULL, "<acl> <path>+",		"Search ACL(s)" };

COMMAND rename_command =
  { "rename-access",    rename_cmd,     NULL, "<new>=<old>[,...] <path>+", 	"Rename ACL entries" };

COMMAND inherit_command =
  { "inherit-access",   inherit_cmd,	NULL, "<path>+",		"Propage ACL(s) inheritance" };


COMMAND *acl_commands[] =
  {
   &list_command,
   &set_command,
   &edit_command,
   &touch_command,
   &get_command,
#if 0
   &sort_command,
   &strip_command,
#endif
   &copy_command,
   &delete_command,
   &find_command,
   &rename_command,
   &inherit_command,
   NULL,
  };
