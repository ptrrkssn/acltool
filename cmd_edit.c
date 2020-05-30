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
    int type; /* 0 = regex, '=' = exact, '+' positive match, '-' = negative match */
    
    /* Regex style */
    int avail;
    regex_t preg;

    /* Simple style */
    gacl_entry_t ep;
  } filter;
  struct {
    /* Generic data */
    char *data;

    /* ACE entry */
    gacl_entry_t ep;
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
  ACECR *cur = NULL;
  char *tbuf = NULL;
  ACECR **next;
  char *bp, *ep;
  char *es;
  jmp_buf saved_error_env;
  int rc;

  
  if ((rc = error_catch(saved_error_env)) != 0) {
    fprintf(stderr, "acecr_from_text: error-catched\n");
    
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
  
    error_return(rc, saved_error_env);
  }
  
  bp = tbuf = s_dup(buf);
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
      return error(1, errno, "Malloc");
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
      int m_type = 0;
      int c;

      
      *ep++ = '\0';
      
      cur->filter.avail = 1;
      if (strchr("!=+-", *ep))
	switch (c = *ep++) {
	case '!': /* Inverse match */
	  cur->filter.avail = -1;
	  break;
	  
	default:
	  m_type = c;
	  break;
	}
    
      if (!m_type) {
	int ec;
	
	ec = regcomp(&cur->filter.preg, es, rflags);
	if (ec) {
	  char errbuf[1024];
	  
	  regerror(ec, &cur->filter.preg, errbuf, sizeof(errbuf));
	  return error(1, 0, "%s: Regex: %s", es, errbuf);
	}
      } else {
	cur->filter.ep = malloc(sizeof(*(cur->filter.ep)));
	if (!cur->filter.ep) {
	  return error(1, errno, "Malloc");
	  goto Fail;
	}

	cur->filter.type = m_type;
	
	if (_gacl_entry_from_text(es, cur->filter.ep, 0) < 0) {
	  return error(1, 0, "%s: Invalid GACL Entry", es);
	  goto Fail;
	}
      }
      es = ep;
      
    }

    while (isspace(*es))
      ++es;
    
    if (!isalpha(*es)) {
      return error(1, 0, "%s: Invalid ACL Entry");
      goto Fail;
    }
    
    cur->cmd = *es++;
    
    for (ep = es; *ep && !isspace(*ep); ++ep)
      ;
    if (*ep)
      *ep++ = '\0';
    if (*es)
      cur->modifiers = s_dup(es);

    es = ep;
    if (isspace(*es)) {
      while (isspace(*es))
	++es;
    }
    if (*es) {
      cur->change.data = s_dup(es);
      if (!cur->change.data) {
	return error(1, errno, "Memory");
	goto Fail;
      }
      
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep) {
	return error(1, errno, "Malloc");
	goto Fail;
      }

      if (_gacl_entry_from_text(es, cur->change.ep, 0) < 0) {
	return error(1, 0, "Invalid ACL Entry");
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
  
  bp = tbuf = s_dup(buf);
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
    memset(cur->filter.ep, 0, sizeof(*(cur->filter.ep)));
    
    if (_gacl_entry_from_text(es, cur->filter.ep, GACL_TEXT_RELAXED) < 0)
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
      
      if (_gacl_entry_from_text(es, cur->change.ep, 0) < 0)
	goto Fail;
      
      cur->modifiers = s_dup(ep);
      cur->cmd = 's';
      
    } else {
      /* Simple change - only update permissions on matching ACEs
       *
       * acl=<tag>:<perms>[:<flags>][:<type>]]
       *
       * format: <acl>[,<acl>]*
       */
      cur->change.ep = malloc(sizeof(*(cur->change.ep)));
      if (!cur->change.ep)
	goto Fail;
      
      *(cur->change.ep) = *(cur->filter.ep);
      cur->filter.type = 0; /* Ignore 'permissions part at match' */
      if (cur->change.ep->perms == 0)
	cur->cmd = 'd';
      else
	cur->cmd = 'S';
    }

    
    *next = cur;
    next = &cur->next;
  }

  if (tbuf)
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
ace_match(gacl_entry_t oae,
	  gacl_entry_t mae,
	  int mflags) {
  /* Matching ACE */
  gacl_tag_t mtt;
  gacl_entry_type_t met;
  uid_t *mip;
  gacl_permset_t mps;
  gacl_flagset_t mfs;

  /* Current ACE */
  gacl_tag_t ott;
  gacl_entry_type_t oet;
  gacl_permset_t ops;
  gacl_flagset_t ofs;
  uid_t *oip;

  
  gacl_get_tag_type(mae, &mtt);
  gacl_get_tag_type(oae, &ott);

  if (ott != mtt)
      return 0;
  
  gacl_get_entry_type_np(mae, &met);
  mip = gacl_get_qualifier(mae);
  
  gacl_get_entry_type_np(oae, &oet);
  oip = gacl_get_qualifier(oae);
  

  if ((ott == GACL_TAG_TYPE_USER || ott == GACL_TAG_TYPE_GROUP) && (!oip || !mip || *oip != *mip)) {
    if (mip)
      gacl_free(mip);
    if (oip)
      gacl_free(oip);
    return 0;
  }

  if (mip)
    gacl_free(mip);
  if (oip)
    gacl_free(oip);
  
  /* Check the ACE type set */
    if (met != oet)
      return 0;

  if (gacl_get_permset(mae, &mps) < 0 ||
      gacl_get_flagset_np(mae, &mfs) < 0)
    return -1;
  
  if (gacl_get_permset(oae, &ops) < 0 ||
      gacl_get_flagset_np(oae, &ofs) < 0)
    return -1;




  /* Check the flag set */
  if (*mfs != *ofs)
    return 0;

  switch (mflags) {
  case 0:
    break;
    
  case '=':
    if (*mps != *ops)
      return 0;
    break;

  case '+':
    if ((*ops & *mps) != *mps)
      return 0;
    break;
    
  case '-':
    if ((*ops & *mps) != 0)
      return 0;
    break;
  }

  return 1;
}



static int
cmd_edit_ace(gacl_entry_t oae,
	     gacl_entry_t nae) {
  /* Old ACE */
  gacl_tag_t ott;
  gacl_entry_type_t oet;
  gacl_permset_t ops;
  gacl_flagset_t ofs;
	  
  /* New ACE */
  gacl_tag_t ntt;
  gacl_entry_type_t net;
  gacl_permset_t nps;
  gacl_flagset_t nfs;
  uid_t *nip = NULL;

  
  /* Get old ACE */
  gacl_get_tag_type(oae, &ott);
  gacl_get_entry_type_np(oae, &oet);
	  
  if (gacl_get_permset(oae, &ops) < 0 ||
      gacl_get_flagset_np(oae, &ofs) < 0)
    return -1;

  /* Get new ACE */
  gacl_get_tag_type(nae, &ntt);
  gacl_get_entry_type_np(nae, &net);
  nip = gacl_get_qualifier(nae);
  
  if (gacl_get_permset(nae, &nps) < 0 ||
      gacl_get_flagset_np(nae, &nfs) < 0)
    goto Fail;

  /* Update the tag type */
  if (gacl_set_tag_type(oae, ntt) < 0)
    goto Fail;
  
  if (nip)
    if (gacl_set_qualifier(oae, nip) < 0)
      goto Fail;
  
  if (gacl_set_permset(oae, nps) < 0)
    goto Fail;
  
  if (gacl_set_flagset_np(oae, nfs) < 0)
    goto Fail;
  
  if (gacl_set_entry_type_np(oae, net) < 0)
    goto Fail;

  free(nip);
  return 1;

 Fail:
  if (nip)
    gacl_free(nip);
  return -1;
}

static int
cmd_edit_crace(ACECR *cr,
	       gacl_entry_t oae) {
  return cmd_edit_ace(oae, cr->change.ep);
  
}
RANGE *
range_filter(RANGE *old, gacl_entry_t fae, int flags, gacl_t ap) {
  RANGE *new = NULL;
  gacl_entry_t ae;
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
    for (p = 0; gacl_get_entry(ap, p == 0 ? GACL_FIRST_ENTRY : GACL_NEXT_ENTRY, &ae) == 1; p++) {
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
		   gacl_t ap) {
  RANGE *new = NULL;
  gacl_entry_t ae;
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

      if (gacl_entry_to_text(ae, buf, sizeof(buf), 0) < 0)
	continue;
      
      rc = regexec(preg, buf, 0, NULL, 0);
      switch (rc) {
      case 0:
	range_add(&new, p, p);
      case REG_NOMATCH:
	break;
      default:
	regerror(rc, preg, errbuf, sizeof(errbuf));
	error(1, 0, "%s: Regex: %s", buf, errbuf);
	return NULL;
      }
		    
      if (p >= ap->ac-1)
	break;
    }
  } else {
    /* Scan whole ACL */
    for (p = 0; gacl_get_entry(ap, p == 0 ? GACL_FIRST_ENTRY : GACL_NEXT_ENTRY, &ae) == 1; p++) {
      if (gacl_entry_to_text(ae, buf, sizeof(buf), GACL_TEXT_STANDARD) < 0)
	continue;

      rc = regexec(preg, buf, 0, NULL, 0);
      switch (rc) {
      case 0:
	range_add(&new, p, p);
      case REG_NOMATCH:
	break;
      default:
	regerror(rc, preg, errbuf, sizeof(errbuf));
	error(1, 0, "%s: Regex: %s", buf, errbuf);
	return NULL;
      }
    }
  }
  
  return new;
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
  SCRIPT *sp, *next;

  
  if (!spp)
    return;
  
  for (sp = *spp; sp; sp = next) {
    next = sp->next;
    acecr_free(sp->cr);
    free(sp);
  }
  *spp = NULL;
}
  

static int
walker_edit(const char *path,
	    const struct stat *sp,
	    size_t base,
	    size_t level,
	    void *vp) {
  gacl_t oap = NULL;
  gacl_t nap = NULL;
  SCRIPT *script = NULL;
  int rc = 0;
  int pos = 0;
  int p_line = 0;
  jmp_buf saved_error_env;


  if ((rc = error_catch(saved_error_env)) != 0) {
    if (oap)
      gacl_free(oap);
    if(nap)
      gacl_free(nap);

    error_return(rc, saved_error_env);
  }
  
  oap = get_acl(path, sp);  
  if (!oap)
    return error(1, errno, "%s: Getting ACL", path);

  nap = gacl_dup(oap);
  if (!nap) {
    int ec = errno;
    
    gacl_free(oap);
    return error(1, ec, "%s: Internal Fault (gacl_dup)", path);
  }

  /* Execute script - all registered CR chains in sequence */
  for (script = (SCRIPT *) vp; script; script = script->next) {
    ACECR *cr = script->cr;

    /* Loop around executing each CR until end or one gives an error */
    for (rc = 0; rc == 0 && cr; cr = cr->next) {
      gacl_entry_t nae;
      int p1, p;
      int nm = 0;
      RANGE *range = NULL;

      
      /* Make sure this change request is valid for this file type */
      if (cr->ftypes && (sp->st_mode & cr->ftypes) == 0)
	continue;

      if (cr->filter.avail) {
	if (cr->filter.ep)
	  range = range_filter(cr->range, cr->filter.ep, cr->filter.type, nap);
	else
	  range = range_filter_regex(cr->range, &cr->filter.preg, cr->filter.type, nap);
	if (!range && cr->cmd != 'S')
	  continue;
      }
      else
	range = cr->range;

      switch (cr->cmd) {
      case 'd': /* Delete ACEs - do it backwards */
	if (range_len(range) > 0) {
	  p = RANGE_NONE;
	  while (range_prev(range, &p) == 1) {
	    if (p == RANGE_END)
	      p = nap->ac-1;
	    if (gacl_delete_entry_np(nap, p) < 0) {
	      rc = -1;
	      break;
	    }
	  }
	  pos = p;
	} else {
	  if (gacl_delete_entry_np(nap, pos) < 0) {
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
	    if (print_ace(nap, p, GACL_TEXT_STANDARD) < 0) {
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
	  if (print_ace(nap, pos, GACL_TEXT_STANDARD) < 0) {
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
	if (gacl_create_entry_np(&nap, &nae, p1) < 0)
	  return error(1, errno, "Creating ACL Entry @ %d", p1);
	else if (gacl_copy_entry(nae, cr->change.ep) < 0)
	  return error(1, errno, "Copying ACL Entry");
	break;
	
      case '=': /* Replace ACE at position */
	if (range_last(range, &p1) != 1)
	  p1 = pos;
	if (_gacl_get_entry(nap, p1, &nae) < 0)
	  rc = -1;
	else if (gacl_copy_entry(nae, cr->change.ep) < 0)
	  rc = -1;
	break;
	
      case 'x': /* eXchange ACEs p1<->p2 */
	rc = -1;
	errno = ENOSYS;
	break;
	
      case 's': /* Substitue ACEs */
      case 'S': /* Substitue ACEs (simple-change) */
	if (!range && cr->cmd == 'S') {
	  GACL_ENTRY *oep = cr->change.ep;

	  /* 
	   * Try to find optimal insertion point for a new ACE. This code assumes the 
	   * ACL is sorted where users < groups < everyone and with deny < allow.
	   */
	  for (pos = 0; pos < nap->ac; ++pos) {
	    GACL_ENTRY *nep = &nap->av[pos];
	    
	    if (oep->tag.type < nep->tag.type)
	      break;
	    if (oep->tag.type > nep->tag.type)
	      continue;
	    if (oep->tag.type == GACL_TAG_TYPE_USER || oep->tag.type == GACL_TAG_TYPE_GROUP) {
	      if (oep->tag.ugid < nep->tag.ugid)
		break;
	      if (oep->tag.ugid > nep->tag.ugid)
		break;
	    }
	    if (oep->type > nep->type)
	      break;
	  }
	  goto AddACE;
	}
	
	if (range_len(range) > 0) {
	  gacl_entry_t ae;
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
	  gacl_entry_t ae;

	  p = 0;
	  while (_gacl_get_entry(nap, p, &ae) == 1) {
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

	    ++p;
	  }
	  if (rc > 0)
	    rc = 0;
	}

	if (nm == 0) {
	AddACE:
	  /* Add ACE entry if no match found */
	  if (gacl_create_entry_np(&nap, &nae, pos) < 0)
	    return error(1, errno, "Creating ACL Entry @ %d", pos);

	  if (gacl_copy_entry(nae, cr->change.ep) < 0)
	    return error(1, errno, "Copying ACL Entry");
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
  if (rc < 0)
    error(1, errno, "%s: Setting ACL", path);

  gacl_free(oap);
  gacl_free(nap);
  return 0;
}

static int
editopt_handler(const char *name,
		const char *vs,
		unsigned int type,
		const void *svp,
		void *dvp,
		const char *a0) {
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
   { "execute", 'e', OPTS_TYPE_STR, editopt_handler, NULL, "Commands (from string)" },
   { "file",    'E', OPTS_TYPE_STR, editopt_handler, NULL, "Commands (from file)" },
   { NULL, 0, 0, NULL, NULL, NULL },
  };


static int
edit_cmd(int argc,
	 char **argv) {
  int rc, i;
  ACECR *cr;
  

  if (argc < 2) {
    script_free(&edit_script);
    error(1, 0, "Missing required arguments");
  }

  i = 1;
  if (!edit_script && argc > 2) {
    cr = NULL;
    if (acecr_from_simple_text(&cr, argv[i]) < 0)
      error(1, 0, "%s: Invalid simple change request", argv[i]);
    if (script_add(&edit_script, cr) < 0)
      error(1, 0, "%s: Unable to add simple change request", argv[i]);
    ++i;
  }
  
  if (!edit_script) {
    error(1, 0, "Invalid or no change request");
    return 1;
  }

  rc = aclcmd_foreach(argc-i, argv+i, walker_edit, edit_script);

  script_free(&edit_script);
  return rc;
}


/* Command definition */
COMMAND edit_command =
  { "edit-access",  edit_cmd,  edit_options,  "[<change>] <path>+",  "Edit ACL(s)"  };
   
