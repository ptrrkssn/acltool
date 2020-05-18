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
#include <regex.h>

#include "acltool.h"
#include "range.h"




/* 
 * ACL change request list 
 */
typedef struct ace_cr {
  mode_t ftypes;
  RANGE *range;
  struct {
    /* Regex style */
    int avail;
    regex_t preg;

    /* Simple style */
    acl_entry_t ep;
    GACE_EDIT_FLAGS flags;
  } filter;
  struct {
    /* Generic data */
    char *data;

    /* ACE entry */
    acl_entry_t ep;
    GACE_EDIT_FLAGS flags;
  } change;
  int cmd;
  char *modifiers;
  struct ace_cr *next;
} ACECR;

/* ACL script list */
typedef struct script {
  ACECR *cr;
  struct script *next;
} SCRIPT;


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

  /* Get each CR */
  while ((es = strsep(&bp, ";\n\r")) != NULL) {
    while (isspace(*es))
      ++es;

    if (!*es || *es == '#')
      continue;
    
    cur = malloc(sizeof(*cur));
    if (!cur) {
      goto Fail;
    }
    memset(cur, 0, sizeof(*cur));

    while (isspace(*es))
      ++es;
    
    /* Get file types */
    if (*es == '{' && (ep = strchr(++es, '}')) != NULL) {
      *ep++ = '\0';
      
      str2filetype(es, &cur->ftypes);
      es = ep;
    }
    
    while (isspace(*es))
      ++es;
    
    /* Get ACE range */
    range_adds(&cur->range, (const char **) &es);
    
    while (isspace(*es))
      ++es;

    /* Get filter */
    if (*es == '/' && (ep = strchr(++es, '/')) != NULL) {
      int rflags = REG_EXTENDED;
      
      *ep++ = '\0';
      
      cur->filter.avail = 1;
      while (strspn(ep, "iv"))
	switch (*ep++) {
	case 'i': /* Ignore case */
	  rflags |= REG_ICASE;
	  break;
	case 'v': /* Inverse match */
	  cur->filter.avail = -1;
	  break;
	}
    
      if (config.f_regex) {
	int ec;
	
	ec = regcomp(&cur->filter.preg, es, rflags);
	if (ec) {
	  char errbuf[1024];
	  
	  regerror(ec, &cur->filter.preg, errbuf, sizeof(errbuf));
	  fprintf(stderr, "%s: Error: %s: %s\n", argv0, es, errbuf);
	  goto Fail;
	}
      } else {
	cur->filter.ep = malloc(sizeof(*(cur->filter.ep)));
	if (!cur->filter.ep)
	  goto Fail;
	
	if (_gacl_entry_from_text(es, cur->filter.ep, &cur->filter.flags) < 0)
	  goto Fail;
      }
      es = ep;
      
    }

    while (isspace(*es))
      ++es;
    
    if (!isalpha(*es))
      goto Fail;
    
    cur->cmd = *es++;
    
    for (ep = es; *ep && !isspace(*ep); ++ep)
      ;
    if (*ep)
      *ep++ = '\0';
    if (*es)
      cur->modifiers = strdup(es);

    es = ep;
    if (isspace(*es)) {
      while (isspace(*es))
	++es;
    }
    if (*es) {
      cur->change.data = strdup(es);
      if (!cur->change.data)
	goto Fail;
      
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep)
	goto Fail;

      if (_gacl_entry_from_text(es, cur->change.ep, &cur->change.flags) < 0) {
	goto Fail;
      }
    }
    
    *next = cur;
    next = &cur->next;
  }

  free(tbuf);
  return 0;

 Fail:
  if (tbuf)
    free(tbuf);
  if (cur) {
    if (cur->filter.avail) {
      if (cur->filter.ep)
	free(cur->filter.ep);
      else
	regfree(&cur->filter.preg);
    }
    if (cur->change.data)
      free(cur->change.data);
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
acecr_from_simple_text(ACECR **head,
		       const char *buf) {
  ACECR *cur, **next;
  char *tbuf, *ep, *bp, *es, *ftp;


  if (!buf)
    return -1;

  while (isspace(*buf))
    ++buf;

  if (!*buf)
    return -1;
  
  bp = tbuf = strdup(buf);
  if (!tbuf)
    return -1;

  /* Locate end of program list */
  next = head;
  for (cur = *head; cur; cur = cur->next)
    next = &cur->next;
  
  while ((es = strsep(&bp, ",;")) != NULL) {
    cur = malloc(sizeof(*cur));
    if (!cur)
      goto Fail;
    memset(cur, 0, sizeof(*cur));
    
    /* Get ?<filetype> matchlist */
    ftp = strchr(es, '?');
    if (ftp) {
      *ftp++ = '\0';
      str2filetype(ftp, &cur->ftypes);
    }
    
    ep = NULL;
    if (*es == '/') {
      ++es;
      /* Locate end of match */
      ep = strchr(es, '/');
      if (ep)
	*ep++ = '\0';
    }
    
    cur->filter.ep = malloc(sizeof(*(cur->filter.ep)));
    if (!cur->filter.ep)
      goto Fail;
    
    if (_gacl_entry_from_text(es, cur->filter.ep, &cur->filter.flags) < 0)
      goto Fail;
    
    cur->filter.avail = 1;
    if (ep) {
      /* Matched change - only update matching ACEs
       *
       * acl=<tag>:<perms>[:<flags>][:<type>]]
       * change=/<acl>/<acl>/[<modifiers>]
       *
       * format: <change>[,<change]*
       */
      es = ep;
      
      /* Locate end of change */
      ep = strchr(es, '/');
      if (ep)
	*ep++ = '\0';
      
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep)
	goto Fail;
      
      if (_gacl_entry_from_text(es, cur->change.ep, &cur->change.flags) < 0)
	goto Fail;
      
      if (ep)
	cur->modifiers = strdup(ep);
    } else {
      /* Simple change - only update permissions on matching ACEs
       *
       * acl=<tag>:<perms>[:<flags>][:<type>]]
       *
       * format: <acl>[,<acl>]*
       */
      acl_permset_t ps;
      
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep)
	goto Fail;
      
      *(cur->change.ep) = *(cur->filter.ep);
      cur->change.flags = cur->filter.flags;
      
      switch (cur->filter.flags & GACE_EDIT_TAG_MASK) {
      case GACE_EDIT_TAG_ADD:
      case GACE_EDIT_TAG_ALL:
	acl_get_permset(cur->filter.ep, &ps);
	acl_clear_perms(ps);
	acl_set_permset(cur->filter.ep, ps);
	acl_free(ps);
	cur->filter.flags &= ~GACE_EDIT_PERM_MASK;
	cur->filter.flags |= GACE_EDIT_PERM_ALL;
	break;
      case GACE_EDIT_TAG_SUB:
	puts("SUB");
      }
    }

    cur->cmd = 's';
    
    *next = cur;
    next = &cur->next;
  }
  
  return 0;

 Fail:
  if (tbuf)
    free(tbuf);
  if (cur) {
    if (cur->filter.avail) {
      if (cur->filter.ep)
	free(cur->filter.ep);
      else
	regfree(&cur->filter.preg);
    }
    if (cur->change.data)
      free(cur->change.data);
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
ace_match(acl_entry_t oae,
	  acl_entry_t mae,
	  int mflags) {
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
  acl_get_tag_type(mae, &mtt);
  acl_get_entry_type_np(mae, &met);
  mip = acl_get_qualifier(mae);
  
  if (acl_get_permset(mae, &mps) < 0 ||
      acl_get_flagset_np(mae, &mfs) < 0)
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
  switch (mflags & GACE_EDIT_TYPE_MASK) {
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
  switch (mflags & GACE_EDIT_FLAG_MASK) {
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
  switch (mflags & GACE_EDIT_PERM_MASK) {
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
cmd_edit_ace(acl_entry_t oae,
	     acl_entry_t nae,
	     GACE_EDIT_FLAGS flags) {
  /* Old ACE */
  acl_tag_t ott;
  acl_entry_type_t oet;
  acl_permset_t ops;
  acl_flagset_t ofs;
	  
  /* New ACE */
  acl_tag_t ntt;
  acl_entry_type_t net;
  uid_t *nip;
  acl_permset_t nps;
  acl_flagset_t nfs;

  
  /* Get old ACE */
  acl_get_tag_type(oae, &ott);
  acl_get_entry_type_np(oae, &oet);
	  
  if (acl_get_permset(oae, &ops) < 0 ||
      acl_get_flagset_np(oae, &ofs) < 0)
    return -1;

  /* Get new ACE */
  acl_get_tag_type(nae, &ntt);
  acl_get_entry_type_np(nae, &net);
  nip = acl_get_qualifier(nae);
  
  if (acl_get_permset(nae, &nps) < 0 ||
      acl_get_flagset_np(nae, &nfs) < 0)
    return -1;

  /* Update the tag type */
  switch (flags & GACE_EDIT_TAG_MASK) {
  case GACE_EDIT_TAG_SUB:
    goto Fail;
    
  case GACE_EDIT_TAG_ADD:
  case GACE_EDIT_TAG_NONE:
    acl_set_tag_type(oae, ntt);
    if (nip)
      acl_set_qualifier(oae, nip);
  }
  
  /* Update the permissions set */
  switch (flags & GACE_EDIT_PERM_MASK) {
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
  switch (flags & GACE_EDIT_FLAG_MASK) {
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
  switch (flags & GACE_EDIT_TYPE_MASK) {
  case GACE_EDIT_TYPE_SUB:
    goto Fail;
    
  case GACE_EDIT_TYPE_ADD:
  case GACE_EDIT_TAG_NONE:
    acl_set_entry_type_np(oae, net);
    break;
  }

  return 1;

 Fail:
  return -1;
}

static int
cmd_edit_crace(ACECR *cr,
	       acl_entry_t oae) {
  return cmd_edit_ace(oae, cr->change.ep, cr->change.flags);
  
}
RANGE *
range_filter(RANGE *old, acl_entry_t fae, int flags, acl_t ap) {
  RANGE *new = NULL;
  acl_entry_t ae;
  int p;
  

  if (old) {
    /* Just check selected entries */
    
    if (range_len(old) < 1)
      return NULL;
  
    p = RANGE_NONE;
    while (range_next(old, &p) == 1) {
      if (p == RANGE_END)
	p = ap->ac-1;
      
      if (_gacl_get_entry(ap, p, &ae) < 0)
	continue;
  
      if (ace_match(ae, fae, flags) == 1)
	range_add(&new, p, p);
		    
      if (p >= ap->ac-1)
	break;
    }
  } else {
    /* Scan whole ACL */
    for (p = 0; acl_get_entry(ap, p == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; p++) {
      if (ace_match(ae, fae, flags) == 1) {
	range_add(&new, p, p);
      }
    }
  }
  
  return new;
}


RANGE *
range_filter_regex(RANGE *old,
		   regex_t *preg,
		   int flags,
		   acl_t ap) {
  RANGE *new = NULL;
  acl_entry_t ae;
  int p;
  char buf[1024], errbuf[1024];
  int rc;

  if (old) {
    /* Just check selected entries */
    
    if (range_len(old) < 1)
      return NULL;
  
    p = RANGE_NONE;
    while (range_next(old, &p) == 1) {
      if (p == RANGE_END)
	p = ap->ac-1;
      
      if (_gacl_get_entry(ap, p, &ae) < 0)
	continue;

      if (acl_entry_to_text(ae, buf, sizeof(buf), 0) < 0)
	continue;
      
      rc = regexec(preg, buf, 0, NULL, 0);
      switch (rc) {
      case 0:
	range_add(&new, p, p);
      case REG_NOMATCH:
	break;
      default:
	regerror(rc, preg, errbuf, sizeof(errbuf));
	fprintf(stderr, "%s: Error: %s: %s\n", argv0, buf, errbuf);
	exit(1);
      }
		    
      if (p >= ap->ac-1)
	break;
    }
  } else {
    /* Scan whole ACL */
    for (p = 0; acl_get_entry(ap, p == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; p++) {
      if (acl_entry_to_text(ae, buf, sizeof(buf), ACL_TEXT_STANDARD_NP) < 0)
	continue;

      rc = regexec(preg, buf, 0, NULL, 0);
      switch (rc) {
      case 0:
	range_add(&new, p, p);
      case REG_NOMATCH:
	break;
      default:
	regerror(rc, preg, errbuf, sizeof(errbuf));
	fprintf(stderr, "%s: Error: %s: %s\n", argv0, buf, errbuf);
	exit(1);
      }
    }
  }
  
  return new;
}


static int
walker_edit(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  acl_t oap, nap;
  SCRIPT *script;
  int rc = 0;
  int pos = 0;
  int p_line = 0;

  oap = get_acl(path, sp);  
  if (!oap) {
    fprintf(stderr, "%s: Error: %s: Getting ACL: %s\n", argv0, path, strerror(errno));
    return 1;
  }

  nap = acl_dup(oap);
  if (!nap) {
    acl_free(oap);
    fprintf(stderr, "%s: Error: %s: Internal Fault (acl_dup): %s\n", argv0, path, strerror(errno));
    return 1;
  }

  /* Execute script - all registered CR chains in sequence */
  for (script = (SCRIPT *) vp; script; script = script->next) {
    ACECR *cr = script->cr;

    /* Loop around executing each CR until end or one gives an error */
    for (rc = 0; rc == 0 && cr; cr = cr->next) {
      acl_entry_t nae;
      int p1, p;
      int nm = 0;
      RANGE *range = NULL;

      
      /* Make sure this change request is valid for this file type */
      if (cr->ftypes && (sp->st_mode & cr->ftypes) == 0) {
	if (config.f_debug)
	  fprintf(stderr, "*** File type mismatch - skipping\n");
	continue;
      }

      if (cr->filter.avail) {
	if (cr->filter.ep)
	  range = range_filter(cr->range, cr->filter.ep, cr->filter.flags, nap);
	else
	  range = range_filter_regex(cr->range, &cr->filter.preg, cr->filter.flags, nap);
	if (!range) {
	  if (config.f_debug)
	    fprintf(stderr, "*** Range filter mismatch - skipping\n");
	  continue;
	}
      }
      else
	range = cr->range;

      if (config.f_debug) {
	fprintf(stderr, "*** Range: ");
	range_print(range, stderr);
	fprintf(stderr, "\n*** Action: %c\n", cr->cmd);
      }

      switch (cr->cmd) {
      case 'd': /* Delete ACEs - do it backwards */
	if (range_len(range) > 0) {
	  p = RANGE_NONE;
	  while (range_prev(range, &p) == 1) {
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
	
      case 'n': /* Print ACE(s), with line numbers */
	p_line = 1;
      case 'p': /* Print ACE(s) */
	if (range_len(range) > 0) {
	  p = RANGE_NONE;
	  while (range_next(range, &p) == 1) {
	    if (p == RANGE_END)
	      p = nap->ac-1;

	    if (!config.f_noprefix)
	      printf("%-20s\t", path);
	    if (p_line)
	      printf("%-4d\t", p);
	    if (print_ace(nap, p, ACL_TEXT_STANDARD_NP) < 0) {
	      rc = -1;
	      break;
	    }
	    
	    if (p >= nap->ac-1)
	      break;
	  }
	  pos = p;
	} else {
	  if (!config.f_noprefix)
	    printf("%-20s\t", path);
	  if (p_line)
	    printf("%-4d\t", pos);
	  if (print_ace(nap, pos, ACL_TEXT_STANDARD_NP) < 0) {
	    rc = -1;
	    break;
	  }
	}
	break;
	
      case 'a': /* Append ACE after position */
      case 'i': /* Insert ACE at position */
	if (range_last(range, &p1) != 1)
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
	if (range_last(range, &p1) != 1)
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
	if (range_len(range) > 0) {
	  acl_entry_t ae;
	  int p = RANGE_NONE;
	  
	  while (range_next(range, &p) == 1) {
	    if (p == RANGE_END)
	      p = nap->ac-1;
	    
	    pos = p;
	    
	    if (_gacl_get_entry(nap, p, &ae) < 0) {
	      rc = -1;
	      break;
	    }
	    
	    rc = cmd_edit_crace(cr, ae);
	    if (rc < 0) {
	      rc = -1;
	      break;
	    }
	    if (rc == 1)
	      ++nm;
	    
	    if (p >= nap->ac-1)
	      break;
	  }
	} else {
	  acl_entry_t ae;
	  
	  for (p = 0; acl_get_entry(nap, p == 0 ? ACL_FIRST_ENTRY : ACL_NEXT_ENTRY, &ae) == 1; p++) {
	    pos = p;
	    
	    rc = cmd_edit_crace(cr, ae);
	    if (rc < 0) {
	      rc = -1;
	      break;
	    }

	    if (rc == 1) {
	      ++nm;

	      /* 'Global' search & replace or stop at first match? */
	      if (cr->modifiers && !strchr(cr->modifiers, 'g'))
		break;
	    }
	  }
	  if (rc > 0)
	    rc = 0;
	}

	/* Add ACE entry if no match found? */
	if (nm == 0 && cr->change.flags & GACE_EDIT_TAG_ADD) {
	  if (acl_create_entry_np(&nap, &nae, pos) < 0) {
	    fprintf(stderr, "Unable to create ACE at %d\n", pos);
	    rc = -1;
	  }
	  else if (acl_copy_entry(nae, cr->change.ep) < 0) {
	    fprintf(stderr, "Unable to copy ACE: %s\n", strerror(errno));
	    rc = -1;
	  }
	}
	break;
	
      default:
	errno = ENOSYS;
	rc = -1;
      }
      
      if (range != cr->range)
	range_free(&range);
    }
  }
  
  gacl_clean(nap);

  rc = set_acl(path, sp, nap, oap);
  if (rc < 0) {
    goto Fail;
  }

  acl_free(oap);
  acl_free(nap);
  return 0;

 Fail:
  acl_free(oap);
  acl_free(nap);
  return 1;
}

static SCRIPT *edit_script = NULL;


static int
script_add(SCRIPT **spp,
	   ACECR *cr) {
  SCRIPT *new;
  

  if (!spp)
    return -1;
  
  new = malloc(sizeof(*new));
  if (!new)
    return -1;

  memset(new, 0, sizeof(*new));
  new->cr = cr;
  new->next = NULL;

  while (*spp)
    spp = &(*spp)->next;

  *spp = new;
  return 0;
}

static void
acecr_free(ACECR *cr) {
  while (cr) {
    ACECR *next = cr->next;

    if (cr->filter.avail) {
      if (cr->filter.ep)
	free(cr->filter.ep);
      else
	regfree(&cr->filter.preg);
    }
    if (cr->change.ep)
      free(cr->change.ep);
    if (cr->modifiers)
      free(cr->modifiers);
    free(cr);
    cr = next;
  }
}

static void
script_free(SCRIPT **spp) {
  SCRIPT **next;

  for (; *spp; spp = next) {
    next = &(*spp)->next;
    acecr_free((*spp)->cr);
    free(*spp);
  }
  *spp = NULL;
}
  

static int
editopt_handler(const char *name,
		const char *vs,
		unsigned int type,
		const void *svp,
		void *dvp,
		const char *a0) 
{
  ACECR *cr = NULL;

  
  if (!vs)
    return -1;
  
  
  if (strncmp(name, "exec", 4) == 0) {
    if (acecr_from_text(&cr, vs) < 0)
      return -1;
  } else {
    FILE *fp;
    char buf[LINE_MAX];
    int n = 0;
    
    if (strcmp(vs, "-") == 0) {
      fp = stdin;
    } else {
      fp = fopen(vs, "r");
      if (!fp)
	return -1;
    }
    while (fgets(buf, sizeof(buf), fp)) {
      int i;

      for (i = strlen(buf)-1; i >= 0 && isspace(buf[i]); i--)
	;
      buf[i+1] = '\0';
      fprintf(stderr, "'%s'\n", buf);
      n++;
      if (acecr_from_text(&cr, buf) < 0) {
	error(1, 0, "%s: Invalid action at line %d", buf, n);
	return -1;
      }
    }
    if (fp != stdin)
      fclose(fp);
  }

  script_add(&edit_script, cr);
  return 0;
}

static OPTION edit_options[] =
  {
   { "execute", 'e', OPTS_TYPE_STR, editopt_handler, "Commands (from string)" },
   { "file",    'E', OPTS_TYPE_STR, editopt_handler, "Commands (from file)" },
   { NULL, 0, 0, NULL, NULL },
  };


static int
edit_cmd(int argc,
	 char **argv) {
  int rc, i;
  ACECR *cr;
  

  if (argc < 2) {
    fprintf(stderr, "%s: Error: Missing required arguments\n", argv[0]);
    edit_script = NULL;
    return 1;
  }

  i = 1;
  if (!edit_script && argc > 2) {
    cr = NULL;
    acecr_from_simple_text(&cr, argv[i++]);
    script_add(&edit_script, cr);
  }
  
  if (!edit_script) {
    fprintf(stderr, "%s: Error: Invalid/no change request\n", argv0);
    return 1;
  }

  rc = aclcmd_foreach(argc-i, argv+i, walker_edit, edit_script);

  script_free(&edit_script);
  return rc;
}


/* Command definition */
COMMAND edit_command =
  { "edit-access",  edit_cmd,  edit_options,  "[<change>] <path>+",  "Edit ACL(s)"  };
   
