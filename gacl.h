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

#if defined(__FreeBSD__)

#if GACL_MASK_FREEBSD_IMPLEMENTATION
#define acl_t            freebsd_acl_t
#define acl_entry_t      freebsd_acl_entry_t
#define acl_type_t       freebsd_acl_type_t

#define acl_get_file     freebsd_acl_get_file
#define acl_get_link_np  freebsd_acl_get_link_np
#define acl_get_fd       freebsd_acl_get_fd
#define acl_get_fd_np    freebsd_acl_get_fd_np

#define acl_set_file     freebsd_acl_set_file
#define acl_set_link_np  freebsd_acl_set_link_np
#define acl_set_fd       freebsd_acl_set_fd
#define acl_set_fd_np    freebsd_acl_set_fd_np

#define GACL_FREEBSD_EMULATION 1
#endif

#define GACL_SOLARIS_EMULATION 1

#include <sys/acl.h>

#if GACL_MASK_FREEBSD_IMPLEMENTATION
#undef acl_t
#undef acl_entry_t
#undef acl_type_t
#endif

#elif defined(__sun__)

#define GACL_FREEBSD_EMULATION 1

/* Mask some types that conflict */
#define acl_t      sun_acl_t
#define acl_type_t sun_acl_type_t

#include <sys/acl.h>

#undef acl_t
#undef acl_type_t

#elif defined(__linux__)

#define GACL_FREEBSD_EMULATION 1
#define GACL_SOLARIS_EMULATION 1

#include "nfs4.h"

#endif



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

typedef uint16_t GACE_FLAGSET;
typedef uint16_t GACE_FLAG;

typedef uint32_t GACE_PERMSET;
typedef uint32_t GACE_PERM;


#define GACL_FIRST_ENTRY 0
#define GACL_NEXT_ENTRY  1



typedef enum gace_tag {
  GACE_TAG_UNDEFINED = 0x0000,
  GACE_TAG_USER_OBJ  = 0x0001,
  GACE_TAG_USER      = 0x0002,
  GACE_TAG_GROUP_OBJ = 0x0004,
  GACE_TAG_GROUP     = 0x0008,
  GACE_TAG_MASK      = 0x0010,
  GACE_TAG_OTHER_OBJ = 0x0020,
  GACE_TAG_EVERYONE  = 0x0040,
} GACE_TAG;

#define GACE_TAG_OTHER GACE_TAG_OTHER_OBJ

#if defined(__linux__)

/* Wild guess - probably not right for Linux */
#define GACL_MAX_ENTRIES 1024

typedef enum gace_type {
  GACE_TYPE_ALLOW = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
  GACE_TYPE_DENY  = NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
  GACE_TYPE_AUDIT = NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE,
  GACE_TYPE_ALARM = NFS4_ACE_SYSTEM_ALARM_ACE_TYPE,
} GACE_TYPE;

#define GACE_FLAG_FILE_INHERIT          NFS4_ACE_FILE_INHERIT_ACE
#define GACE_FLAG_DIRECTORY_INHERIT     NFS4_ACE_DIRECTORY_INHERIT_ACE
#define GACE_FLAG_NO_PROPAGATE_INHERIT  NFS4_ACE_NO_PROPAGATE_INHERIT_ACE
#define GACE_FLAG_INHERIT_ONLY          NFS4_ACE_INHERIT_ONLY_ACE
#define GACE_FLAG_SUCCESSFUL_ACCESS     NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG
#define GACE_FLAG_FAILED_ACCESS         NFS4_ACE_FAILED_ACCESS_ACE_FLAG

#ifdef NFS4_ACE_INHERITED_ACE
#define GACE_FLAG_INHERITED             NFS4_ACE_INHERITED_ACE
#endif


#elif defined(__sun__)

#define GACL_MAX_ENTRIES MAX_ACL_ENTRIES

/* Use Sun's definitions */
typedef enum gace_type {
  GACE_TYPE_ALLOW = ACE_ACCESS_ALLOWED_ACE_TYPE,
  GACE_TYPE_DENY  = ACE_ACCESS_DENIED_ACE_TYPE,
  GACE_TYPE_AUDIT = ACE_SYSTEM_AUDIT_ACE_TYPE,
  GACE_TYPE_ALARM = ACE_SYSTEM_ALARM_ACE_TYPE,
} GACE_TYPE;

#define GACE_FLAG_FILE_INHERIT          ACE_FILE_INHERIT_ACE
#define GACE_FLAG_DIRECTORY_INHERIT     ACE_DIRECTORY_INHERIT_ACE
#define GACE_FLAG_NO_PROPAGATE_INHERIT  ACE_NO_PROPAGATE_INHERIT_ACE
#define GACE_FLAG_INHERIT_ONLY          ACE_INHERIT_ONLY_ACE
#define GACE_FLAG_SUCCESSFUL_ACCESS     ACE_SUCCESSFUL_ACCESS_ACE_FLAG
#define GACE_FLAG_FAILED_ACCESS         ACE_FAILED_ACCESS_ACE_FLAG
#ifdef ACE_INHERITED_ACE
#define GACE_FLAG_INHERITED             ACE_INHERITED_ACE
#endif

#endif
 
#define GACE_FLAGS_ALL \
  (GACE_FLAG_FILE_INHERIT|GACE_FLAG_DIRECTORY_INHERIT|GACE_FLAG_NO_PROPAGATE_INHERIT| \
   GACE_FLAG_INHERIT_ONLY|GACE_FLAG_SUCCESSFUL_ACCESS|GACE_FLAG_FAILED_ACCESS|GACE_FLAG_INHERITED)


#if defined(__sun__)

#define GACE_READ_DATA           ACE_READ_DATA
#define GACE_LIST_DIRECTORY      ACE_LIST_DIRECTORY
#define GACE_WRITE_DATA          ACE_WRITE_DATA
#define GACE_ADD_FILE            ACE_ADD_FILE
#define GACE_APPEND_DATA         ACE_APPEND_DATA
#define GACE_ADD_SUBDIRECTORY    ACE_ADD_SUBDIRECTORY
#define GACE_READ_NAMED_ATTRS    ACE_READ_NAMED_ATTRS
#define GACE_WRITE_NAMED_ATTRS   ACE_WRITE_NAMED_ATTRS
#define GACE_EXECUTE             ACE_EXECUTE
#define GACE_DELETE_CHILD        ACE_DELETE_CHILD
#define GACE_READ_ATTRIBUTES     ACE_READ_ATTRIBUTES
#define GACE_WRITE_ATTRIBUTES    ACE_WRITE_ATTRIBUTES
#define GACE_DELETE              ACE_DELETE
#define GACE_READ_ACL            ACE_READ_ACL
#define GACE_WRITE_ACL           ACE_WRITE_ACL
#define GACE_WRITE_OWNER         ACE_WRITE_OWNER
#define GACE_SYNCHRONIZE         ACE_SYNCHRONIZE

#elif defined(__linux__)

#define GACE_READ_DATA           NFS4_ACE_READ_DATA
#define GACE_LIST_DIRECTORY      NFS4_ACE_LIST_DIRECTORY
#define GACE_WRITE_DATA          NFS4_ACE_WRITE_DATA
#define GACE_ADD_FILE            NFS4_ACE_ADD_FILE
#define GACE_APPEND_DATA         NFS4_ACE_APPEND_DATA
#define GACE_ADD_SUBDIRECTORY    NFS4_ACE_ADD_SUBDIRECTORY
#define GACE_READ_NAMED_ATTRS    NFS4_ACE_READ_NAMED_ATTRS
#define GACE_WRITE_NAMED_ATTRS   NFS4_ACE_WRITE_NAMED_ATTRS
#define GACE_EXECUTE             NFS4_ACE_EXECUTE
#define GACE_DELETE_CHILD        NFS4_ACE_DELETE_CHILD
#define GACE_READ_ATTRIBUTES     NFS4_ACE_READ_ATTRIBUTES
#define GACE_WRITE_ATTRIBUTES    NFS4_ACE_WRITE_ATTRIBUTES
#define GACE_DELETE              NFS4_ACE_DELETE
#define GACE_READ_ACL            NFS4_ACE_READ_ACL
#define GACE_WRITE_ACL           NFS4_ACE_WRITE_ACL
#define GACE_WRITE_OWNER         NFS4_ACE_WRITE_OWNER
#define GACE_SYNCHRONIZE         NFS4_ACE_SYNCHRONIZE

#endif


/* POSIX.1e */
#define GACE_PERM_BITS           (GACE_EXECUTE | GACE_WRITE | GACE_READ)
#define GACE_POSIX1E_BITS        (GACE_EXECUTE | GACE_WRITE | GACE_READ)

/* NFSv4 / ZFS */

#define GACE_FULL_SET \
  (GACE_READ_DATA | GACE_WRITE_DATA |					  \
   GACE_APPEND_DATA | GACE_READ_NAMED_ATTRS | GACE_WRITE_NAMED_ATTRS |	  \
   GACE_EXECUTE | GACE_DELETE_CHILD | GACE_READ_ATTRIBUTES |		  \
   GACE_WRITE_ATTRIBUTES | GACE_DELETE | GACE_READ_ACL | GACE_WRITE_ACL | \
   GACE_WRITE_OWNER | GACE_SYNCHRONIZE)

#define GACE_MODIFY_SET \
  (GACE_FULL_SET & ~(GACE_WRITE_ACL | GACE_WRITE_OWNER))

#define GACE_READ_SET \
  (GACE_READ_DATA | GACE_READ_NAMED_ATTRS | GACE_READ_ATTRIBUTES | GACE_READ_ACL)

#define GACE_WRITE_SET \
  (GACE_WRITE_DATA | GACE_APPEND_DATA | GACE_WRITE_NAMED_ATTRS | GACE_WRITE_ATTRIBUTES)

#define GACE_NFS4_PERM_BITS \
  GACE_FULL_SET


typedef char GACE_EDIT;

typedef struct gace {
  GACE_TAG tag;
  uid_t id;
  GACE_PERMSET perms;
  GACE_FLAGSET flags;
  GACE_TYPE type;
  GACL_BRAND brand;
  GACE_EDIT edit;
} GACE;


typedef struct gacl {
  GACL_TYPE type;
  int ac;
  int as;
  int ap;
  GACE av[0];
} GACL;



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
gacl_is_trivial_np(GACL *ap,
		   int *trivialp);


extern GACL *
gacl_strip_np(GACL *ap,
	      int recalculate_mask);

extern int
gacl_init_entry(GACE *ep);


extern int
gacl_create_entry_np(GACL **app,
		     GACE **epp,
		     int index);

extern int
gacl_create_entry(GACL **app,
		  GACE **epp);

extern int
gacl_add_entry_np(GACL **app,
		  GACE *ep,
		  int index);

extern int
gacl_delete_entry_np(GACL *ap,
		     int index);

extern int
gacl_delete_entry(GACL *ap,
		  GACE *ep);

extern int
gacl_copy_entry(GACE *dep,
		GACE *sep);


extern int
gacl_get_entry(GACL *ap,
	       int eid,
	       GACE **epp);



#define GACL_F_SYMLINK_NOFOLLOW 0x0001

GACL *
_gacl_get_fd_file(int fd,
		  const char *path,
		  GACL_TYPE type,
		  int flags);

int
_gacl_set_fd_file(int fd,
		  const char *path,
		  GACL_TYPE type,
		  GACL *ap,
		  int flags);

extern GACL *
gacl_get_file(const char *path,
	      GACL_TYPE type);

/* Beware that Solaris doesn't support doing ACL operations on symbolic links */
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

/* Beware that Solaris doesn't support doing ACL operations on symbolic links */
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
gacl_set_tag_type(GACE *ep,
		  GACE_TAG et);

extern int
gacl_get_tag_type(GACE *ep,
		  GACE_TAG *etp);

extern void *
gacl_get_qualifier(GACE *ep);

extern int
gacl_set_qualifier(GACE *ep,
		   const void *qp);

extern int
gacl_get_permset(GACE *ep,
		 GACE_PERMSET **eppp);

extern int
gacl_set_permset(GACE *ep,
		 GACE_PERMSET *psp);

extern int
_gacl_merge_permset(GACE_PERMSET *d,
		    GACE_PERMSET *s,
		    int f);

extern int
_gacl_empty_permset(GACE_PERMSET *p);

extern int
gacl_get_perm_np(GACE_PERMSET *epp,
		 GACE_PERM p);

extern int
gacl_clear_perms(GACE_PERMSET *psp);


extern int
gacl_clean(GACL *ap);

extern int
gacl_add_perm(GACE_PERMSET *psp,
	      GACE_PERM p);

extern int
gacl_delete_perm(GACE_PERMSET *psp,
		 GACE_PERM p);

extern int
gacl_get_flagset_np(GACE *ep,
		    GACE_FLAGSET **fspp);

extern int
_gacl_empty_flagset(GACE_FLAGSET *f);

extern int
gacl_set_flagset_np(GACE *ep,
		    GACE_FLAGSET *fsp);

extern int
_gacl_merge_flagset(GACE_FLAGSET *d,
		    GACE_FLAGSET *s,
		    int f);

extern int
gacl_clear_flags_np(GACE_FLAGSET *fsp);

extern int
gacl_get_flag_np(GACE_FLAGSET *fsp,
		 GACE_FLAG f);

extern int
gacl_add_flag_np(GACE_FLAGSET *fsp,
		 GACE_FLAG f);

extern int
gacl_delete_flag_np(GACE_FLAGSET *fsp,
		    GACE_FLAG f);

extern int
gacl_get_entry_type_np(GACE *ep,
		       GACE_TYPE *etp);

extern int
gacl_set_entry_type_np(GACE *ep,
		       GACE_TYPE et);



#define GACL_TEXT_VERBOSE      0x0010
#define GACL_TEXT_NUMERIC_IDS  0x0020
#define GACL_TEXT_APPEND_ID    0x0040

extern ssize_t
gacl_entry_tag_to_text(GACE *ep,
		       char *buf,
		       size_t bufsize,
		       int flags);

extern ssize_t
gacl_entry_permset_to_text(GACE *ep,
			   char *buf,
			   size_t bufsize,
			   int flags);

extern ssize_t
gacl_entry_flagset_to_text(GACE *ep,
			   char *buf,
			   size_t bufsize,
			   int flags);

extern ssize_t
gacl_entry_type_to_text(GACE *ep,
			char *buf,
			size_t bufsize,
			int flags);


extern ssize_t
gacl_entry_to_text(GACE *ep,
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


#if GACL_FREEBSD_EMULATION

typedef GACL *acl_t;
typedef GACE *acl_entry_t;
typedef GACE_TAG acl_tag_t;
typedef GACE_PERM acl_perm_t;
typedef GACE_FLAG acl_flag_t;
typedef GACE_TYPE acl_entry_type_t;
typedef GACE_PERMSET *acl_permset_t;
typedef GACE_FLAGSET *acl_flagset_t;

#define ACL_TYPE_NFS4             GACL_TYPE_NFS4
#define ACL_MAX_ENTRIES           GACL_MAX_ENTRIES

#define ACL_UNDEFINED_TAG         GACE_TAG_UNDEFINED
#define ACL_USER_OBJ              GACE_TAG_USER_OBJ 
#define ACL_USER                  GACE_TAG_USER     
#define ACL_GROUP_OBJ             GACE_TAG_GROUP_OBJ
#define ACL_GROUP                 GACE_TAG_GROUP    
#define ACL_MASK                  GACE_TAG_MASK     
#define ACL_OTHER_OBJ             GACE_TAG_OTHER_OBJ
#define ACL_OTHER                 GACE_TAG_OTHER_OBJ
#define ACL_EVERYONE              GACE_TAG_EVERYONE 

#define ACL_ENTRY_TYPE_ALLOW      GACE_TYPE_ALLOW
#define ACL_ENTRY_TYPE_DENY       GACE_TYPE_DENY
#define ACL_ENTRY_TYPE_AUDIT      GACE_TYPE_AUDIT
#define ACL_ENTRY_TYPE_ALARM      GACE_TYPE_ALARM

#define ACL_READ_DATA             GACE_READ_DATA
#define ACL_LIST_DIRECTORY        GACE_LIST_DIRECTORY
#define ACL_WRITE_DATA            GACE_WRITE_DATA
#define ACL_ADD_FILE              GACE_ADD_FILE
#define ACL_APPEND_DATA           GACE_APPEND_DATA
#define ACL_ADD_SUBDIRECTORY      GACE_ADD_SUBDIRECTORY
#define ACL_READ_NAMED_ATTRS      GACE_READ_NAMED_ATTRS
#define ACL_WRITE_NAMED_ATTRS     GACE_WRITE_NAMED_ATTRS
#define ACL_EXECUTE               GACE_EXECUTE
#define ACL_DELETE_CHILD          GACE_DELETE_CHILD
#define ACL_READ_ATTRIBUTES       GACE_READ_ATTRIBUTES
#define ACL_WRITE_ATTRIBUTES      GACE_WRITE_ATTRIBUTES
#define ACL_DELETE                GACE_DELETE
#define ACL_READ_ACL              GACE_READ_ACL
#define ACL_WRITE_ACL             GACE_WRITE_ACL
#define ACL_WRITE_OWNER           GACE_WRITE_OWNER
#define ACL_SYNCHRONIZE           GACE_SYNCHRONIZE

#define ACL_FIRST_ENTRY           GACL_FIRST_ENTRY
#define ACL_NEXT_ENTRY            GACL_NEXT_ENTRY

#define ACL_ENTRY_FILE_INHERIT          GACE_FLAG_FILE_INHERIT
#define ACL_ENTRY_DIRECTORY_INHERIT     GACE_FLAG_DIRECTORY_INHERIT
#define ACL_ENTRY_NO_PROPAGATE_INHERIT  GACE_FLAG_NO_PROPAGATE_INHERIT
#define ACL_ENTRY_INHERIT_ONLY          GACE_FLAG_INHERIT_ONLY
#define ACL_ENTRY_SUCCESSFUL_ACCESS     GACE_FLAG_SUCCESSFUL_ACCESS
#define ACL_ENTRY_FAILED_ACCESS         GACE_FLAG_FAILED_ACCESS
#ifdef GACE_FLAG_INHERITED
#define ACL_ENTRY_INHERITED             GACE_FLAG_INHERITED
#endif

#define ACL_TEXT_VERBOSE          GACL_TEXT_VERBOSE
#define ACL_TEXT_NUMERIC_IDS      GACL_TEXT_NUMERIC_IDS
#define ACL_TEXT_APPEND_ID        GACL_TEXT_APPEND_ID

#define acl_init                  gacl_init
#define acl_free                  gacl_free
#define acl_get_brand_np          gacl_get_brand_np
#define acl_dup                   gacl_dup
#define acl_is_trivial_np         gacl_is_trivial_np
#define acl_strip_np              gacl_strip_np
#define acl_create_entry_np       gacl_create_entry_np
#define acl_create_entry          gacl_create_entry
#define acl_delete_entry_np       gacl_delete_entry_np
#define acl_copy_entry            gacl_copy_entry
#define acl_get_entry             gacl_get_entry
#define acl_get_file              gacl_get_file
#define acl_get_link_np           gacl_get_link_np
#define acl_get_fd                gacl_get_fd
#define acl_get_fd_np             gacl_get_fd_np
#define acl_set_file              gacl_set_file
#define acl_set_link_np           gacl_set_link_np
#define acl_set_fd                gacl_set_fd
#define acl_set_fd_np             gacl_set_fd_np
#define acl_set_tag_type          gacl_set_tag_type
#define acl_get_tag_type          gacl_get_tag_type
#define acl_set_qualifier         gacl_set_qualifier
#define acl_get_qualifier         gacl_get_qualifier
#define acl_get_permset           gacl_get_permset
#define acl_set_permset           gacl_set_permset
#define acl_get_perm_np           gacl_get_perm_np
#define acl_clear_perms           gacl_clear_perms
#define acl_add_perm              gacl_add_perm
#define acl_delete_perm           gacl_delete_perm
#define acl_get_flagset_np        gacl_get_flagset_np
#define acl_set_flagset_np        gacl_set_flagset_np
#define acl_clear_flags_np        gacl_clear_flags_np
#define acl_get_flag_np           gacl_get_flag_np
#define acl_add_flag_np           gacl_add_flag_np
#define acl_delete_flag_np        gacl_delete_flag_np
#define acl_get_entry_type_np     gacl_get_entry_type_np
#define acl_set_entry_type_np     gacl_set_entry_type_np
#define acl_to_text_np            gacl_to_text_np
#define acl_to_text               gacl_to_text
#define acl_delete_file_np        gacl_delete_file_np
#define acl_delete_link_np        gacl_delete_link_np
#define acl_delete_fd_np          gacl_delete_fd_np
#define acl_delete_def_file       gacl_delete_def_file
#define acl_delete_def_link_np    gacl_delete_def_link_np
#define acl_from_text             gacl_from_text



/* GACL extensions */

#define acl_init_entry            gacl_init_entry
#define acl_add_entry_np          gacl_add_entry_np

#define acl_entry_tag_to_text     gacl_entry_tag_to_text
#define acl_entry_permset_to_text gacl_entry_permset_to_text
#define acl_entry_flagset_to_text gacl_entry_flagset_to_text
#define acl_entry_to_text         gacl_entry_to_text
#endif

#if GACL_SOLARIS_EMULATION
#define acl                       gacl_get_solaris
#define facl                      gacl_fget_solaris
#endif


#endif
