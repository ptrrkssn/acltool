/*
 * gacl.h - Generic ACLs - Emulate FreeBSD ACL functionality on Linux & Solaris
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

#ifndef GACL_H
#define GACL_H 1

#include <stdint.h>
#include <sys/types.h>


typedef enum gacl_brand {
  GACL_BRAND_NONE  = 0,
  GACL_BRAND_POSIX = 3,
  GACL_BRAND_NFS4  = 4,
} GACL_BRAND;


typedef enum gacl_type {
  GACL_TYPE_NONE    = 0,
  GACL_TYPE_ACCESS  = 1,
  GACL_TYPE_DEFAULT = 2,
  GACL_TYPE_NFS4    = 4,
} GACL_TYPE;


typedef enum gacl_tag_type {
  GACL_TAG_TYPE_UNKNOWN   = 0x0000,
  GACL_TAG_TYPE_USER_OBJ  = 0x0001,
  GACL_TAG_TYPE_USER      = 0x0002,
  GACL_TAG_TYPE_GROUP_OBJ = 0x0004,
  GACL_TAG_TYPE_GROUP     = 0x0008,
  GACL_TAG_TYPE_MASK      = 0x0010, /* POSIX.1e */
  GACL_TAG_TYPE_OTHER     = 0x0020, /* POSIX.1e */
  GACL_TAG_TYPE_EVERYONE  = 0x0040,
} GACL_TAG_TYPE;


typedef struct gacl_entry_tag {
  GACL_TAG_TYPE type;
  uid_t ugid;
  char *name;
} GACL_TAG;


typedef uint32_t GACL_PERM;
typedef uint32_t GACL_PERMSET;

#define GACL_PERM_EXECUTE             	0x00000001

#define GACL_PERM_READ_DATA           	0x00000008
#define GACL_PERM_LIST_DIRECTORY      	GACL_PERM_READ_DATA

#define GACL_PERM_WRITE_DATA          	0x00000010
#define GACL_PERM_ADD_FILE            	GACL_PERM_WRITE_DATA

#define GACL_PERM_APPEND_DATA         	0x00000020
#define GACL_PERM_ADD_SUBDIRECTORY    	GACL_PERM_APPEND_DATA

#define GACL_PERM_READ_NAMED_ATTRS    	0x00000040
#define GACL_PERM_WRITE_NAMED_ATTRS   	0x00000080

#define GACL_PERM_DELETE_CHILD        	0x00000100
#define GACL_PERM_READ_ATTRIBUTES     	0x00000200
#define GACL_PERM_WRITE_ATTRIBUTES    	0x00000400
#define GACL_PERM_DELETE              	0x00000800
#define GACL_PERM_READ_ACL            	0x00001000
#define GACL_PERM_WRITE_ACL           	0x00002000
#define GACL_PERM_WRITE_OWNER         	0x00004000
#define GACL_PERM_SYNCHRONIZE         	0x00008000

#define GACL_PERM_FULL_SET \
  (GACL_PERM_READ_DATA | GACL_PERM_WRITE_DATA |					  \
   GACL_PERM_APPEND_DATA | GACL_PERM_READ_NAMED_ATTRS | GACL_PERM_WRITE_NAMED_ATTRS |	  \
   GACL_PERM_EXECUTE | GACL_PERM_DELETE_CHILD | GACL_PERM_READ_ATTRIBUTES |		  \
   GACL_PERM_WRITE_ATTRIBUTES | GACL_PERM_DELETE | GACL_PERM_READ_ACL | GACL_PERM_WRITE_ACL | \
   GACL_PERM_WRITE_OWNER | GACL_PERM_SYNCHRONIZE)

#define GACL_PERM_MODIFY_SET \
  (GACL_PERM_FULL_SET & ~(GACL_PERM_WRITE_ACL | GACL_PERM_WRITE_OWNER))

#define GACL_PERM_READ_SET \
  (GACL_PERM_READ_DATA | GACL_PERM_READ_NAMED_ATTRS | GACL_PERM_READ_ATTRIBUTES | GACL_PERM_READ_ACL)

#define GACL_PERM_WRITE_SET \
  (GACL_PERM_WRITE_DATA | GACL_PERM_APPEND_DATA | GACL_PERM_WRITE_NAMED_ATTRS | GACL_PERM_WRITE_ATTRIBUTES)

#define GACL_PERM_NFS4_BITS \
  GACL_PERM_FULL_SET


typedef uint16_t GACL_FLAG;
typedef uint16_t GACL_FLAGSET;

#define GACL_FLAG_OI 0x0001
#define GACL_FLAG_CI 0x0002
#define GACL_FLAG_NP 0x0004
#define GACL_FLAG_IO 0x0008
#define GACL_FLAG_ID 0x0010
#define GACL_FLAG_SA 0x0040
#define GACL_FLAG_FA 0x0080

#define GACL_FLAG_FILE_INHERIT          GACL_FLAG_OI
#define GACL_FLAG_DIRECTORY_INHERIT     GACL_FLAG_CI
#define GACL_FLAG_NO_PROPAGATE_INHERIT  GACL_FLAG_NP
#define GACL_FLAG_INHERIT_ONLY          GACL_FLAG_IO
#define GACL_FLAG_INHERITED             GACL_FLAG_ID
#define GACL_FLAG_SUCCESSFUL_ACCESS     GACL_FLAG_SA
#define GACL_FLAG_FAILED_ACCESS         GACL_FLAG_FA

#define	GACL_FLAG_BITS \
  (GACL_FLAG_FILE_INHERIT |       \
   GACL_FLAG_DIRECTORY_INHERIT |  \
   GACL_FLAG_NO_PROPAGATE_INHERIT \
   GACL_FLAG_INHERIT_ONLY |       \
   GACL_FLAG_SUCCESSFUL_ACCESS |  \
   GACL_FLAG_FAILED_ACCESS |      \
   GACL_FLAG_INHERITED)


typedef enum gacl_entry_type {
  GACL_ENTRY_TYPE_UNDEFINED = -1,
  GACL_ENTRY_TYPE_ALLOW     = 0,
  GACL_ENTRY_TYPE_DENY      = 1,
  GACL_ENTRY_TYPE_AUDIT     = 2,
  GACL_ENTRY_TYPE_ALARM     = 3,
} GACL_ENTRY_TYPE;


typedef struct gacl_entry {
  GACL_TAG tag;
  GACL_PERMSET perms;
  GACL_FLAGSET flags;
  GACL_ENTRY_TYPE type;
} GACL_ENTRY;


typedef struct gacl {
  GACL_TYPE type;
  char owner[128];
  char group[128];
  int ac;
  int as;
  int ap;
  GACL_ENTRY av[0];
} GACL;


typedef GACL *gacl_t;
typedef GACL_ENTRY *gacl_entry_t;

typedef GACL_TAG_TYPE gacl_tag_t;

typedef GACL_PERM gacl_perm_t;
typedef GACL_PERMSET *gacl_permset_t;

typedef GACL_FLAG gacl_flag_t;
typedef GACL_FLAGSET *gacl_flagset_t;

typedef GACL_ENTRY_TYPE gacl_entry_type_t;


#define GACL_MIN_ENTRIES      16
#define GACL_DEFAULT_ENTRIES 128


extern GACL *
gacl_init(int count);

extern int
gacl_free(void *op);

extern int
gacl_get_brand_np(GACL *ap,
		  GACL_BRAND *bp);

extern GACL *
gacl_dup(GACL *ap);

extern int
gacl_match(GACL *ap,
	   GACL *mp);

extern int
_gacl_entry_match(GACL_ENTRY *aep,
		  GACL_ENTRY *mep,
		  int how);

extern int
gacl_entry_match(GACL_ENTRY *aep,
		 GACL_ENTRY *mep);

extern GACL *
gacl_sort(GACL *ap);

extern GACL *
gacl_merge(GACL *ap);

extern int
gacl_is_trivial_np(GACL *ap,
		   int *trivialp);

extern GACL *
gacl_strip_np(GACL *ap,
	      int recalculate_mask);

extern int
gacl_init_entry(GACL_ENTRY *ep);

extern int
gacl_create_entry_np(GACL **app,
		     GACL_ENTRY **epp,
		     int index);

extern int
gacl_create_entry(GACL **app,
		  GACL_ENTRY **epp);

extern int
gacl_add_entry_np(GACL **app,
		  GACL_ENTRY *ep,
		  int index);

extern int
gacl_delete_entry_np(GACL *ap,
		     int index);

extern int
gacl_delete_entry(GACL *ap,
		  GACL_ENTRY *ep);

extern int
gacl_copy_entry(GACL_ENTRY *dep,
		GACL_ENTRY *sep);


extern int
_gacl_entries(GACL *ap);


#define GACL_FIRST_ENTRY 0
#define GACL_NEXT_ENTRY  1

extern int
_gacl_get_entry(GACL *ap,
		int pos,
		GACL_ENTRY **epp);

extern int
gacl_get_entry(GACL *ap,
	       int eid,
	       GACL_ENTRY **epp);


extern GACL *
gacl_get_file(const char *path,
	      GACL_TYPE type);

/* Beware that Solaris and Linux currently doesn't support doing ACL operations on symbolic links */
GACL *
gacl_get_link_np(const char *path,
		 GACL_TYPE type);

extern GACL *
gacl_get_fd_np(int fd,
	       GACL_TYPE type);

extern GACL *
gacl_get_fd(int fd);

extern int
gacl_set_file(const char *path,
	      GACL_TYPE type,
	      GACL *ap);

/* Beware that Solaris and Linux doesn't support doing ACL operations on symbolic links */
extern int
gacl_set_link_np(const char *path,
		 GACL_TYPE type,
		 GACL *ap);

extern int
gacl_set_fd_np(int fd,
	       GACL *ap,
	       GACL_TYPE type);

extern int
gacl_set_fd(int fd,
	    GACL *ap);

extern int
gacl_set_tag_type(GACL_ENTRY *ep,
		  GACL_TAG_TYPE et);

extern int
gacl_get_tag_type(GACL_ENTRY *ep,
		  GACL_TAG_TYPE *etp);

extern void *
gacl_get_qualifier(GACL_ENTRY *ep);

extern int
gacl_set_qualifier(GACL_ENTRY *ep,
		   const void *qp);

extern int
gacl_get_permset(GACL_ENTRY *ep,
		 GACL_PERMSET **eppp);

extern int
gacl_set_permset(GACL_ENTRY *ep,
		 GACL_PERMSET *psp);

extern int
gacl_merge_permset(GACL_PERMSET *d,
		   GACL_PERMSET *s,
		   int f);

extern int
gacl_empty_permset(GACL_PERMSET *p);

extern int
gacl_get_perm_np(GACL_PERMSET *epp,
		 GACL_PERM p);

extern int
gacl_clear_perms(GACL_PERMSET *psp);


extern int
gacl_clean(GACL *ap);

extern int
gacl_add_perm(GACL_PERMSET *psp,
	      GACL_PERM p);

extern int
gacl_delete_perm(GACL_PERMSET *psp,
		 GACL_PERM p);

extern int
gacl_get_flagset_np(GACL_ENTRY *ep,
		    GACL_FLAGSET **fspp);

extern int
gacl_empty_flagset(GACL_FLAGSET *f);

extern int
gacl_set_flagset_np(GACL_ENTRY *ep,
		    GACL_FLAGSET *fsp);

extern int
gacl_merge_flagset(GACL_FLAGSET *d,
		   GACL_FLAGSET *s,
		   int f);

extern int
gacl_clear_flags_np(GACL_FLAGSET *fsp);

extern int
gacl_get_flag_np(GACL_FLAGSET *fsp,
		 GACL_FLAG f);

extern int
gacl_add_flag_np(GACL_FLAGSET *fsp,
		 GACL_FLAG f);

extern int
gacl_delete_flag_np(GACL_FLAGSET *fsp,
		    GACL_FLAG f);

extern int
gacl_get_entry_type_np(GACL_ENTRY *ep,
		       GACL_ENTRY_TYPE *etp);

extern int
gacl_set_entry_type_np(GACL_ENTRY *ep,
		       GACL_ENTRY_TYPE et);



#define GACL_TEXT_VERBOSE      0x0010
#define GACL_TEXT_NUMERIC_IDS  0x0020
#define GACL_TEXT_APPEND_ID    0x0040
#define GACL_TEXT_COMPACT      0x1000
#define GACL_TEXT_STANDARD     0x2000

extern ssize_t
gacl_entry_tag_to_text(GACL_ENTRY *ep,
		       char *buf,
		       size_t bufsize,
		       int flags);

extern ssize_t
gacl_entry_permset_to_text(GACL_ENTRY *ep,
			   char *buf,
			   size_t bufsize,
			   int flags);

extern ssize_t
gacl_entry_flagset_to_text(GACL_ENTRY *ep,
			   char *buf,
			   size_t bufsize,
			   int flags);

extern ssize_t
gacl_entry_type_to_text(GACL_ENTRY *ep,
			char *buf,
			size_t bufsize,
			int flags);

extern ssize_t
gacl_entry_to_text(GACL_ENTRY *ep,
		   char *buf,
		   size_t bufsize,
		   int flags);

extern char *
gacl_to_text_np(GACL *ap,
		ssize_t *bsp,
		int flags);

extern char *
gacl_to_text(GACL *ap,
	     ssize_t *bsp);



#define GACL_TEXT_RELAXED  0x0001 /* Do not verify user/group names */

extern int
_gacl_entry_from_text(char *cp,
		      GACL_ENTRY *ep,
		      int flags);

extern int
gacl_entry_from_text(char *buf,
		     GACL_ENTRY *ep);

extern GACL *
gacl_from_text(const char *buf);

extern int
gacl_delete_file_np(const char *path,
		    GACL_TYPE type);

extern int
gacl_delete_link_np(const char *path,
		    GACL_TYPE type);

extern int
gacl_delete_fd_np(int fd,
		  GACL_TYPE type);

extern int
gacl_delete_def_file(const char *path);

extern int
gacl_delete_def_link_np(const char *path);


typedef GACL *acl_t;
typedef GACL_ENTRY *acl_entry_t;
typedef GACL_TAG_TYPE acl_tag_t;
typedef GACL_PERM acl_perm_t;
typedef GACL_FLAG acl_flag_t;
typedef GACL_ENTRY_TYPE acl_entry_type_t;
typedef GACL_PERMSET *acl_permset_t;
typedef GACL_FLAGSET *acl_flagset_t;

#endif
