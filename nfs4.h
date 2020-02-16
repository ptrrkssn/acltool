/*
 * nfs4.h - Constants used from NFSv4 ACLS - taken from RFC7530
 */

#ifndef NFS4_H
#define NFS4_H

#include <stdint.h>

typedef uint32_t nfs4_ace_type;

#define NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE 0
#define NFS4_ACE_ACCESS_DENIED_ACE_TYPE  1
#define NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE   2
#define NFS4_ACE_SYSTEM_ALARM_ACE_TYPE   3


typedef uint32_t nfs4_ace_mask;

#define NFS4_ACE_READ_DATA            0x00000001
#define NFS4_ACE_LIST_DIRECTORY       0x00000001
#define NFS4_ACE_WRITE_DATA           0x00000002
#define NFS4_ACE_ADD_FILE             0x00000002
#define NFS4_ACE_APPEND_DATA          0x00000004
#define NFS4_ACE_ADD_SUBDIRECTORY     0x00000004
#define NFS4_ACE_READ_NAMED_ATTRS     0x00000008
#define NFS4_ACE_WRITE_NAMED_ATTRS    0x00000010
#define NFS4_ACE_EXECUTE              0x00000020
#define NFS4_ACE_DELETE_CHILD         0x00000040
#define NFS4_ACE_READ_ATTRIBUTES      0x00000080
#define NFS4_ACE_WRITE_ATTRIBUTES     0x00000100

#define NFS4_ACE_DELETE               0x00010000
#define NFS4_ACE_READ_ACL             0x00020000
#define NFS4_ACE_WRITE_ACL            0x00040000
#define NFS4_ACE_WRITE_OWNER          0x00080000
#define NFS4_ACE_SYNCHRONIZE          0x00100000


typedef uint32_t nfs4_ace_flag;

#define NFS4_ACE_FILE_INHERIT_ACE             0x00000001
#define NFS4_ACE_DIRECTORY_INHERIT_ACE        0x00000002
#define NFS4_ACE_NO_PROPAGATE_INHERIT_ACE     0x00000004
#define NFS4_ACE_INHERIT_ONLY_ACE             0x00000008
#define NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG   0x00000010
#define NFS4_ACE_FAILED_ACCESS_ACE_FLAG       0x00000020
#define NFS4_ACE_IDENTIFIER_GROUP             0x00000040

/* This is a wild guess - not defined in the RFC but exists in FreeBSD & Solaris */
#define NFS4_ACE_INHERITED_ACE                0x00000080

typedef struct {
  uint32_t len;
  char buf[];
} nfs4_utf8str_mixed;

typedef struct {
  nfs4_ace_type type;
  nfs4_ace_flag flag;
  nfs4_ace_mask access_mask;
  nfs4_utf8str_mixed who;
} nfs4_ace;
#endif
