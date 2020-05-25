/*
 * smb.h
 *
 * Copyright (c) 2019-2020, Peter Eriksson <pen@lysator.liu.se>
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

#ifndef ACLTOOL_SMB_H
#define ACLTOOL_SMB_H 1

#define SMB_ACL_TYPE_ALLOW 0x00
#define SMB_ACL_TYPE_DENY  0x01
#define SMB_ACL_TYPE_AUDIT 0x02
#define SMB_ACL_TYPE_ALARM 0x03

#define SMB_ACL_FLAG_OI   0x01 			/* Object Inherit */
#define SMB_ACL_FLAG_CI   0x02 			/* Container Inherit */
#define SMB_ACL_FLAG_NI   0x04 			/* No Propagate Inherit */
#define SMB_ACL_FLAG_IO   0x08 			/* Inherit Only */

#define SMB_ACL_PERM_GA   0x10000000 		/* Generic All */
#define SMB_ACL_PERM_GE   0x20000000 		/* Generic Execute */
#define SMB_ACL_PERM_GW   0x40000000 		/* Generic Write */
#define SMB_ACL_PERM_GR   0x80000000 		/* Generic Read */

#define SMB_ACL_PERM_RD   0x00000001 		/* Read/List */
#define SMB_ACL_PERM_WD   0x00000002 		/* Write/AddFile */
#define SMB_ACL_PERM_AD   0x00000004 		/* Append/AddSubDir */
#define SMB_ACL_PERM_REA  0x00000008 		/* ReadEA */
#define SMB_ACL_PERM_WEA  0x00000010 		/* WriteEA */
#define SMB_ACL_PERM_X    0x00000020 		/* Execute/Traverse */
#define SMB_ACL_PERM_DC   0x00000040 		/* DeleteChild */
#define SMB_ACL_PERM_RA   0x00000080 		/* ReadAttributes */
#define SMB_ACL_PERM_WA   0x00000100 		/* WriteAttributes */

#define SMB_ACL_PERM_D    0x00010000 		/* Standard Delete */
#define SMB_ACL_PERM_RC   0x00020000 		/* Standard ReadControl */
#define SMB_ACL_PERM_WDAC 0x00040000 		/* Standard WriteDAC */
#define SMB_ACL_PERM_WO   0x00080000		/* Standard WriteOwner */
#define SMB_ACL_PERM_S    0x00100000		/* Synchronize */


/* Standard permissions */
#define SMB_ACL_PERM_R    (SMB_ACL_PERM_RD|SMB_ACL_PERM_RA|SMB_ACL_PERM_REA|SMB_ACL_PERM_RC|SMB_ACL_PERM_S)

#define SMB_ACL_PERM_W    (SMB_ACL_PERM_WD|SMB_ACL_PERM_AD|SMB_ACL_PERM_WA|SMB_ACL_PERM_WEA|SMB_ACL_PERM_RC|SMB_ACL_PERM_S)

#define SMB_ACL_PERM_RX   (SMB_ACL_PERM_R|SMB_ACL_PERM_X)
#define SMB_ACL_PERM_LFC  SMB_ACL_PERM_RX

#define SMB_ACL_PERM_M    (SMB_ACL_PERM_RX|SMB_ACL_PERM_W|SMB_ACL_PERM_D)

#define SMB_ACL_PERM_FC   (SMB_ACL_PERM_M|SMB_ACL_PERM_DC|SMB_ACL_PERM_WDAC|SMB_ACL_PERM_WO)


extern int
smb_lstat(const char *path,
	  struct stat *sp);

extern int
smb_statvfs(const char *path,
	    struct statvfs *sp);

extern int
smb_chdir(const char *path);

extern VFS_DIR *
smb_opendir(const char *path);

extern struct dirent *
smb_readdir(VFS_DIR *dp);

extern int
smb_closedir(VFS_DIR *dp);

extern GACL *
smb_acl_get_file(const char *path);


extern int
smb_listxattr(const char *path,
	      char *buf,
	      size_t bufsize,
	      int flags);

extern int
smb_getxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize);

extern int
smb_setxattr(const char *path,
	     const char *attr,
	     char *buf,
	     size_t bufsize);

extern int
smb_removexattr(const char *path,
		const char *attr);

#endif
