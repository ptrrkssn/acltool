/*
 * gacl_impl.h - Generic ACLs - Emulate FreeBSD ACL functionality on Linux & Solaris
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

#ifndef GACL_IMPL_H
#define GACL_IMPL_H 1


#if defined(__FreeBSD__)
/* ---------------------------------------- FreeBSD - START ---------------------------------------- */

#define GACL_LINUX_EMULATION   1
#define GACL_SOLARIS_EMULATION 1

#define acl_t            freebsd_acl_t
#define acl_entry_t      freebsd_acl_entry_t
#define acl_entry_type_t freebsd_acl_entry_type_t
#define acl_type_t       freebsd_acl_type_t
#define acl_tag_t        freebsd_acl_tag_t
#define acl_perm_t       freebsd_acl_perm_t
#define acl_permset_t    freebsd_acl_permset_t
#define acl_flag_t       freebsd_acl_flag_t
#define acl_flagset_t    freebsd_acl_flagset_t


#ifdef GACL_C_INTERNAL
#define _ACL_PRIVATE 1
#endif

#include <sys/acl.h>

#undef acl_t
#undef acl_entry_t
#undef acl_entry_type_t
#undef acl_type_t
#undef acl_tag_t
#undef acl_perm_t
#undef acl_permset_t
#undef acl_flag_t
#undef acl_flagset_t


/* ---------------------------------------- FreeBSD - END ---------------------------------------- */



#elif defined(__sun__)

/* ---------------------------------------- Solaris - START ---------------------------------------- */

#define GACL_FREEBSD_EMULATION 1
#define GACL_LINUX_EMULATION   1

/* Mask some types that conflict */
#define acl_t      sun_acl_t
#define acl_type_t sun_acl_type_t

#include <sys/acl.h>

#undef acl_t
#undef acl_type_t

#if 0

/* Use Sun's definitions */
typedef enum gacl_entry_type {
  GACL_TYPE_UNDEFINED = -1,
  GACL_TYPE_ALLOW = ACE_ACCESS_ALLOWED_ACE_TYPE,
  GACL_TYPE_DENY  = ACE_ACCESS_DENIED_ACE_TYPE,
  GACL_TYPE_AUDIT = ACE_SYSTEM_AUDIT_ACE_TYPE,
  GACL_TYPE_ALARM = ACE_SYSTEM_ALARM_ACE_TYPE,
} GACL_ENTRY_TYPE;

#define GACL_FLAG_FILE_INHERIT          ACE_FILE_INHERIT_ACE
#define GACL_FLAG_DIRECTORY_INHERIT     ACE_DIRECTORY_INHERIT_ACE
#define GACL_FLAG_NO_PROPAGATE_INHERIT  ACE_NO_PROPAGATE_INHERIT_ACE
#define GACL_FLAG_INHERIT_ONLY          ACE_INHERIT_ONLY_ACE
#define GACL_FLAG_SUCCESSFUL_ACCESS     ACE_SUCCESSFUL_ACCESS_ACE_FLAG
#define GACL_FLAG_FAILED_ACCESS         ACE_FAILED_ACCESS_ACE_FLAG
#ifdef ACE_INHERITED_ACE
#define GACL_FLAG_INHERITED             ACE_INHERITED_ACE
#endif

#define GACL_PERM_READ_DATA           ACE_READ_DATA
#define GACL_PERM_LIST_DIRECTORY      ACE_LIST_DIRECTORY
#define GACL_PERM_WRITE_DATA          ACE_WRITE_DATA
#define GACL_PERM_ADD_FILE            ACE_ADD_FILE
#define GACL_PERM_APPEND_DATA         ACE_APPEND_DATA
#define GACL_PERM_ADD_SUBDIRECTORY    ACE_ADD_SUBDIRECTORY
#define GACL_PERM_READ_NAMED_ATTRS    ACE_READ_NAMED_ATTRS
#define GACL_PERM_WRITE_NAMED_ATTRS   ACE_WRITE_NAMED_ATTRS
#define GACL_PERM_EXECUTE             ACE_EXECUTE
#define GACL_PERM_DELETE_CHILD        ACE_DELETE_CHILD
#define GACL_PERM_READ_ATTRIBUTES     ACE_READ_ATTRIBUTES
#define GACL_PERM_WRITE_ATTRIBUTES    ACE_WRITE_ATTRIBUTES
#define GACL_PERM_DELETE              ACE_DELETE
#define GACL_PERM_READ_ACL            ACE_READ_ACL
#define GACL_PERM_WRITE_ACL           ACE_WRITE_ACL
#define GACL_PERM_WRITE_OWNER         ACE_WRITE_OWNER
#define GACL_PERM_SYNCHRONIZE         ACE_SYNCHRONIZE
#endif

/* ---------------------------------------- Solaris - END ---------------------------------------- */



#elif defined(__linux__)

/* ---------------------------------------- Linux - START ---------------------------------------- */

#define GACL_FREEBSD_EMULATION 1
#define GACL_SOLARIS_EMULATION 1

#include "nfs4.h"

#if 0

typedef enum gacl_entry_type {
  GACL_TYPE_UNDEFINED = -1,
  GACL_TYPE_ALLOW = NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE,
  GACL_TYPE_DENY  = NFS4_ACE_ACCESS_DENIED_ACE_TYPE,
  GACL_TYPE_AUDIT = NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE,
  GACL_TYPE_ALARM = NFS4_ACE_SYSTEM_ALARM_ACE_TYPE,
} GACL_ENTRY_TYPE;

#define GACL_FLAG_FILE_INHERIT          NFS4_ACE_FILE_INHERIT_ACE
#define GACL_FLAG_DIRECTORY_INHERIT     NFS4_ACE_DIRECTORY_INHERIT_ACE
#define GACL_FLAG_NO_PROPAGATE_INHERIT  NFS4_ACE_NO_PROPAGATE_INHERIT_ACE
#define GACL_FLAG_INHERIT_ONLY          NFS4_ACE_INHERIT_ONLY_ACE
#define GACL_FLAG_SUCCESSFUL_ACCESS     NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG
#define GACL_FLAG_FAILED_ACCESS         NFS4_ACE_FAILED_ACCESS_ACE_FLAG

#ifdef NFS4_ACE_INHERITED_ACE
#define GACL_FLAG_INHERITED             NFS4_ACE_INHERITED_ACE
#endif

#define GACL_PERM_READ_DATA           NFS4_ACE_READ_DATA
#define GACL_PERM_LIST_DIRECTORY      NFS4_ACE_LIST_DIRECTORY
#define GACL_PERM_WRITE_DATA          NFS4_ACE_WRITE_DATA
#define GACL_PERM_ADD_FILE            NFS4_ACE_ADD_FILE
#define GACL_PERM_APPEND_DATA         NFS4_ACE_APPEND_DATA
#define GACL_PERM_ADD_SUBDIRECTORY    NFS4_ACE_ADD_SUBDIRECTORY
#define GACL_PERM_READ_NAMED_ATTRS    NFS4_ACE_READ_NAMED_ATTRS
#define GACL_PERM_WRITE_NAMED_ATTRS   NFS4_ACE_WRITE_NAMED_ATTRS
#define GACL_PERM_EXECUTE             NFS4_ACE_EXECUTE
#define GACL_PERM_DELETE_CHILD        NFS4_ACE_DELETE_CHILD
#define GACL_PERM_READ_ATTRIBUTES     NFS4_ACE_READ_ATTRIBUTES
#define GACL_PERM_WRITE_ATTRIBUTES    NFS4_ACE_WRITE_ATTRIBUTES
#define GACL_PERM_DELETE              NFS4_ACE_DELETE
#define GACL_PERM_READ_ACL            NFS4_ACE_READ_ACL
#define GACL_PERM_WRITE_ACL           NFS4_ACE_WRITE_ACL
#define GACL_PERM_WRITE_OWNER         NFS4_ACE_WRITE_OWNER
#define GACL_PERM_SYNCHRONIZE         NFS4_ACE_SYNCHRONIZE
#endif

/* ---------------------------------------- Linux - END ---------------------------------------- */


#elif defined(__APPLE__)
/* ---------------------------------------- MacOS - START ---------------------------------------- */

#define acl_t            macos_acl_t
#define acl_entry_t      macos_acl_entry_t
#define acl_entry_type_t macos_acl_entry_type_t
#define acl_type_t       macos_acl_type_t
#define acl_tag_t        macos_acl_tag_t
#define acl_perm_t       macos_acl_perm_t
#define acl_permset_t    macos_acl_permset_t
#define acl_flag_t       macos_acl_flag_t
#define acl_flagset_t    macos_acl_flagset_t
#define acl_entry_id_t   macos_acl_entry_id_t

#include <sys/acl.h>

#undef acl_t
#undef acl_entry_t
#undef acl_entry_type_t
#undef acl_type_t
#undef acl_tag_t
#undef acl_perm_t
#undef acl_permset_t
#undef acl_flag_t
#undef acl_flagset_t
#undef acl_entry_id_t

/* ---------------------------------------- MacOS - END ---------------------------------------- */

#endif



/*
 * The OS interfaces that get or set an ACL
 */
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

#endif
