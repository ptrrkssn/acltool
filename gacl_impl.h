/*
 * gacl_impl.h - Generic ACLs, OS-specific parts
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

#define _ACL_PRIVATE 1
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


/* ---------------------------------------- Solaris - END ---------------------------------------- */



#elif defined(__linux__)

/* ---------------------------------------- Linux - START ---------------------------------------- */

#define GACL_FREEBSD_EMULATION 1
#define GACL_SOLARIS_EMULATION 1

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
