/*
 * cmd_edit_access.c - ACL command edit-access
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

#include "range.h"



/* ACL change request */
typedef struct ace_cr {
  RANGE *range;
  struct {
    acl_entry_t ep;
    GACE_EDIT_FLAGS flags;
    mode_t ftypes;
  } match;
  char cmd;
  struct {
    acl_entry_t ep;
    GACE_EDIT_FLAGS flags;
  } change;
  char *modifiers;
  struct ace_cr *next;
} ACECR;

/* 
 * acl    = <who>:<perms>[:<flags>][:<type>]
 * match  = acl
 * modifiers = [g]
 * range = <pos>[,<pos>]
 *
 * update = <acl>[/[<modifiers>]]
 * delete = [<range>]d
 * insert = [<pos>]i<acl>
 * append = [<pos>]a<acl>
 * subst  = [<range>][s]/<match>/<acl>[/[<modifiers>]]
 * print  = [<range>]p
 *
 * action  = [<update>|<delete>|<insert>|<append>|<subst>|<print>][@<filetypes]
 * program = <action>[;<action>]*
 *
 * 4d;1,3p
 * 1,$p
 */

static int
acecr_from_text(ACECR **head,
		const char *buf) {
  ACECR *cur, **next;
  char *bp, *tbuf, *ep;
  char *es;
  
  tbuf = NULL;
  bp = tbuf = strdup(buf);
  if (!tbuf)
    return -1;

  /* Locate end of program list */
  next = head;
  for (cur = *head; cur; cur = cur->next)
    next = &cur->next;

  while ((es = strsep(&bp, ";\n\r")) != NULL) {
    char *ftp;

    while (isspace(*es))
      ++es;

    if (!*es || *es == '#')
      continue;
    
    cur = malloc(sizeof(*cur));
    if (!cur) {
      goto Fail;
    }

    cur->next = NULL;
    
    ftp = strchr(es, '@');
    if (ftp) {
      *ftp++ = '\0';
      str2filetype(ftp, &cur->match.ftypes);
    }

    cur->range = NULL;
    range_adds(&cur->range, (const char **) &es);

    while (isspace(*es))
      ++es;
    
    if (isalpha(*es))
      cur->cmd = *es++;
    else if (*es == '/')
      cur->cmd = 's';

    while (isspace(*es))
      ++es;
    
    if (cur->cmd == 's' && *es == '/') {
      ++es;

      /* Locate end of match */
      ep = strchr(es+1, '/');
      if (!ep)
	goto Fail;
      *ep++ = '\0';
      
      cur->match.ep = malloc(sizeof(*(cur->match.ep)));
      if (!cur->match.ep)
	goto Fail;

      if (_gacl_entry_from_text(es, cur->match.ep, &cur->match.flags) < 0) {
	goto Fail;
      }

      es = ep;
      
      /* Locate end of change */
      ep = strchr(es, '/');
      if (ep)
	*ep++ = '\0';
      
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep)
	goto Fail;

      if (_gacl_entry_from_text(es, cur->change.ep, &cur->change.flags) < 0) {
	goto Fail;
      }

      if (ep)
	cur->modifiers = strdup(ep);
    } else if (cur->cmd == 'a' || cur->cmd == 'i') {
      /* Locate end of change (for modifiers) */
      ep = strchr(es, '/');
      if (ep)
	*ep++ = '\0';
      
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep)
	goto Fail;

      if (_gacl_entry_from_text(es, cur->change.ep, &cur->change.flags) < 0) {
	goto Fail;
      }

      if (ep)
	cur->modifiers = strdup(ep);
    }
    
    *next = cur;
    next = &cur->next;
  }

  return 0;

 Fail:
  if (tbuf)
    free(tbuf);
  if (cur) {
    if (cur->match.ep)
      free(cur->match.ep);
    if (cur->change.ep)
      free(cur->change.ep);
    if (cur->modifiers)
      free(cur->modifiers);
    free(cur);
  }
  
  errno = EINVAL;
  return -1;
}





static int
ace_match(ACECR *cr,
	  acl_entry_t oae) {
  /* Matching ACE */
  acl_tag_t mtt;
  acl_entry_type_t met;
  uid_t *mip;
  acl_permset_t mps;
  acl_flagset_t mfs;

  /* Current ACE */
  acl_tag_t ott;
  acl_entry_type_t oet;
  acl_permset_t ops;
  acl_flagset_t ofs;
  uid_t *oip;

  
  /* Get match ACE */
  acl_get_tag_type(cr->match.ep, &mtt);
  acl_get_entry_type_np(cr->match.ep, &met);
  mip = acl_get_qualifier(cr->match.ep);
  
  if (acl_get_permset(cr->match.ep, &mps) < 0 ||
      acl_get_flagset_np(cr->match.ep, &mfs) < 0)
    return -1;
  
  /* Get current ACE */
  acl_get_tag_type(oae, &ott);
  acl_get_entry_type_np(oae, &oet);
  oip = acl_get_qualifier(oae);
  
  if (acl_get_permset(oae, &ops) < 0 ||
      acl_get_flagset_np(oae, &ofs) < 0)
    return -1;


  /* Check the tag type */
  if (ott != mtt)
      return 0;

  if ((ott == ACL_USER || ott == ACL_GROUP) && (!oip || !mip || *oip != *mip))
    return 0;

  /* Check the ACE type set */
  switch (cr->match.flags & GACE_EDIT_TYPE_MASK) {
  case GACE_EDIT_TYPE_NONE:
  case GACE_EDIT_TYPE_ADD:
    if (met != oet)
      return 0;
    break;
    
  case GACE_EDIT_TYPE_SUB:
    if (met == oet)
      return 0;
    break;
  }

  /* Check the flag set */
  switch (cr->match.flags & GACE_EDIT_FLAG_MASK) {
  case GACE_EDIT_FLAG_NONE:
    if (*mfs != *ofs)
      return 0;
    break;
    
  case GACE_EDIT_FLAG_ADD:
    if (*mfs && (*ofs & *mfs) == 0)
      return 0;
    break;
    
  case GACE_EDIT_FLAG_SUB:
    if (*mfs && (*ofs & ~*mfs) != 0)
      return 0;
    break;
  }

  /* Check the permissions set */
  switch (cr->match.flags & GACE_EDIT_PERM_MASK) {
  case GACE_EDIT_PERM_NONE:
    if (*mps != *ops)
      return 0;
    break;
    
  case GACE_EDIT_PERM_ADD:
    if (*mps && (*ops & *mps) == 0)
      return 0;
    break;
    
  case GACE_EDIT_PERM_SUB:
    if (*mps && (*ops & ~*mps) != 0)
      return 0;
    break;
  }

  return 1;
}



static int
cmd_edit_ace(ACECR *cr,
	     acl_entry_t oae) {
  
  /* Matching ACE */
  acl_tag_t mtt;
  acl_entry_type_t met;
  uid_t *mip;
  acl_permset_t mps;
  acl_flagset_t mfs;
  
  /* Change ACE */
  acl_tag_t ntt;
  acl_entry_type_t net;
  uid_t *nip;
  acl_permset_t nps;
  acl_flagset_t nfs;

  /* Current ACE */
  acl_tag_t ott;
  acl_entry_type_t oet;
  acl_permset_t ops;
  acl_flagset_t ofs;
  uid_t *oip;
	  
  
  /* Get match ACE */
  acl_get_tag_type(cr->match.ep, &mtt);
  acl_get_entry_type_np(cr->match.ep, &met);
  mip = acl_get_qualifier(cr->match.ep);
  
  if (acl_get_permset(cr->match.ep, &mps) < 0 ||
      acl_get_flagset_np(cr->match.ep, &mfs) < 0)
    return -1;
  
  /* Get change ACE */
  acl_get_tag_type(cr->change.ep, &ntt);
  acl_get_entry_type_np(cr->change.ep, &net);
  nip = acl_get_qualifier(cr->change.ep);
  
  if (acl_get_permset(cr->change.ep, &nps) < 0 ||
      acl_get_flagset_np(cr->change.ep, &nfs) < 0)
    return -1;
  
  /* Get current ACE */
  acl_get_tag_type(oae, &ott);
  acl_get_entry_type_np(oae, &oet);
  oip = acl_get_qualifier(oae);
	  
  if (acl_get_permset(oae, &ops) < 0 ||
      acl_get_flagset_np(oae, &ofs) < 0)
    return -1;
  
  if (ace_match(cr, oae) != 1)
    return 0;
	  
  /* Update the tag type */
  switch (cr->change.flags & GACE_EDIT_TAG_MASK) {
  case GACE_EDIT_TAG_ADD:
  case GACE_EDIT_TAG_SUB:
    goto Fail;
    
  case GACE_EDIT_TAG_NONE:
    acl_set_tag_type(oae, ntt);
    if (nip)
      acl_set_qualifier(oae, nip);
  }
  
  /* Update the permissions set */
  switch (cr->change.flags & GACE_EDIT_PERM_MASK) {
  case GACE_EDIT_PERM_ADD:
    acl_merge_permset(ops, nps, +1);
    if (acl_set_permset(oae, ops) < 0)
      goto Fail;
    break;
    
  case GACE_EDIT_PERM_SUB:
    acl_merge_permset(ops, nps, -1);
    if (acl_set_permset(oae, ops) < 0)
      goto Fail;
    break;
    
  case GACE_EDIT_PERM_NONE:
    if (acl_set_permset(oae, nps) < 0)
      goto Fail;
  }
  
  /* Update the flag set */
  switch (cr->change.flags & GACE_EDIT_FLAG_MASK) {
  case GACE_EDIT_FLAG_ADD:
    acl_merge_flagset(ofs, nfs, +1);
    if (acl_set_flagset_np(oae, ofs) < 0)
      goto Fail;
    break;
    
  case GACE_EDIT_FLAG_SUB:
    acl_merge_flagset(ofs, nfs, -1);
    if (acl_set_flagset_np(oae, ofs) < 0)
      goto Fail;
    break;
    
  case GACE_EDIT_FLAG_NONE:
    if (acl_set_flagset_np(oae, nfs) < 0)
      goto Fail;
  }
  
  /* Update the type */
  switch (cr->change.flags & GACE_EDIT_TYPE_MASK) {
  case GACE_EDIT_TYPE_ADD:
  case GACE_EDIT_TYPE_SUB:
    goto Fail;
    
  case GACE_EDIT_TAG_NONE:
    acl_set_entry_type_np(oae, net);
    break;
  }

  return 0;

 Fail:
  return -1;
}


static int
walker_edit(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  int j;
  acl_t oap, nap;
  ACECR *cr = (ACECR *) vp;
  int rc = 0;
  int pos = 0;
  

  oap = get_acl(path, sp);  
  if (!oap) {
    fprintf(stderr, "%s: Error: %s: Getting ACL: %s\n", argv0, path, strerror(errno));
    return 1;
  }

  nap = acl_dup(oap);
  if (!nap) {
    fprintf(stderr, "%s: Error: %s: Internal Fault (acl_dup): %s\n", argv0, path, strerror(errno));
    return 1;
  }

  /* Execute program */
  for (rc = 0; rc == 0 && cr; cr = cr->next) {
    acl_entry_t nae;
    int p1, p;

    /* Make sure this change request is valid for this file type */
    if (cr->match.ftypes && (sp->st_mode & cr->match.ftypes) == 0)
      continue;

    switch (cr->cmd) {
    case 'd': /* Delete ACEs - do it backwards */
      if (range_len(cr->range) > 0) {
	p = RANGE_NONE;
	while (range_prev(cr->range, &p) == 1) {
	  if (p == RANGE_END)
	    p = nap->ac-1;
	  if (acl_delete_entry_np(nap, p) < 0) {
	    rc = -1;
	    break;
	  }
	}
	pos = p;
      } else {
	if (acl_delete_entry_np(nap, pos) < 0) {
	  rc = -1;
	  break;
	}
      }
      break;
	
    case 'p': /* Print ACE(s) */
      if (range_len(cr->range) > 0) {
	p = RANGE_NONE;
	while (range_next(cr->range, &p) == 1) {
	  if (p == RANGE_END)
	    p = nap->ac-1;

	  if (print_ace(nap, p, config.f_verbose) < 0) {
	    rc = -1;
	    break;
	  }
	  
	  if (p >= nap->ac-1)
	    break;
	}
	pos = p;
      } else {
	if (print_ace(nap, pos, config.f_verbose) < 0) {
	  rc = -1;
	  break;
	}
      }
      break;
      
    case 'a': /* Append ACE after position */
    case 'i': /* Insert ACE at position */
      if (range_last(cr->range, &p1) != 1)
	p1 = pos;
      if (cr->cmd == 'a')
	++p1;
      if (acl_create_entry_np(&nap, &nae, p1) < 0) {
	fprintf(stderr, "Unable to create ACE at %d\n", p1);
	rc = -1;
      }
      else if (acl_copy_entry(nae, cr->change.ep) < 0) {
	fprintf(stderr, "Unable to copy ACE: %s\n", strerror(errno));
	rc = -1;
      }
      break;
      
    case '=': /* Replace ACE at position */
      if (range_last(cr->range, &p1) != 1)
	p1 = pos;
      if (_gacl_get_entry(nap, p1, &nae) < 0)
	rc = -1;
      else if (acl_copy_entry(nae, cr->change.ep) < 0)
	rc = -1;
      break;

    case 'x': /* eXchange ACEs p1<->p2 */
      rc = -1;
      errno = ENOSYS;
      break;
      
    case 's': /* Substitue ACEs */
      if (range_len(cr->range) > 0) {
	acl_entry_t ae;
	int p = RANGE_NONE;
	
	while (range_next(cr->range, &p) == 1) {
	  if (p == RANGE_END)
	    p = nap->ac-1;

	  if (_gacl_get_entry(nap, p, &ae) < 0) {
	    rc = -1;
	    break;
	  }
	    
	  if (cmd_edit_ace(cr, ae) < 0) {
	    rc = -1;
	    break;
	  }
	  
	  if (p >= nap->ac-1)
	    break;
	}
      } else {
	acl_entry_t ae;
	
	for (j = 0; acl_get_entry(nap, j == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; j++) {
	  if (cmd_edit_ace(cr, ae) < 0) {
	    rc = -1;
	    break;
	  }
	}
      }
      break;

    default:
      errno = ENOSYS;
      rc = -1;
    }
  }
  
  gacl_clean(nap);

  rc = set_acl(path, sp, nap, oap);
  if (rc < 0) {
    goto Fail;
  }

  if (config.f_verbose > 1)
    print_acl(stdout, nap, path, sp);
  
  return 0;

 Fail:
  acl_free(oap);
  acl_free(nap);
  return 1;
}

static ACECR *edit_cr = NULL;

static int
editopt_handler(const char *name,
		const char *vs,
		unsigned int type,
		const void *svp,
		void *dvp,
		const char *a0) 
{
  if (!vs)
    return -1;
  
  if (strcmp(name, "exec") == 0) {
    if (acecr_from_text(&edit_cr, vs) < 0)
      return -1;
  } else {
    FILE *fp;
    char buf[LINE_MAX];

    if (strcmp(vs, "-") == 0) {
      fp = stdin;
    } else {
      fp = fopen(vs, "r");
      if (!fp)
	return -1;
    }
    while (fgets(buf, sizeof(buf), fp))
      if (acecr_from_text(&edit_cr, buf) < 0)
	return -1;
    if (fp != stdin)
      fclose(fp);
  }
  return 0;
}

static OPTION edit_options[] =
  {
   { "exec", 'e', OPTS_TYPE_STR, editopt_handler, "Commands (from string)" },
   { "file", 'f', OPTS_TYPE_STR, editopt_handler, "Commands (from file)" },
   { NULL, 0, 0, NULL, NULL },
  };


static int
edit_cmd(int argc,
	 char **argv) {
  int rc, i;
  ACECR *cr;
  

  if (argc < 2) {
    fprintf(stderr, "%s: Error: Missing required arguments\n", argv[0]);
    edit_cr = NULL;
    return 1;
  }

  i = 1;
  if (!edit_cr && argc > 2)
    acecr_from_text(&edit_cr, argv[i++]);
  
  if (!edit_cr) {
    fprintf(stderr, "%s: Error: Invalid/no change request\n", argv0);
    edit_cr = NULL;
    return 1;
  }

  rc = aclcmd_foreach(argc-i, argv+i, walker_edit, edit_cr);

  cr = edit_cr;
  while (cr) {
    ACECR *next = cr->next;

    if (cr->match.ep)
      free(cr->match.ep);
    if (cr->change.ep)
      free(cr->change.ep);
    if (cr->modifiers)
      free(cr->modifiers);
    free(cr);
    cr = next;
  }
  
  edit_cr = NULL;
  return rc;
}


/* Command definition */
COMMAND edit_command =
  { "edit-access",  edit_cmd,  edit_options,  "[<change>] <path>+",  "Edit ACL(s)"  };
   
