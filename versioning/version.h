#ifndef _VERSION_H
#define _VERSION_H
#pragma once

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define ENDPOINT_NAME				"privacyIDEA"
 
#define VERSION_MAJOR               2
#define VERSION_MINOR               4
#define VERSION_REVISION            0
#define VERSION_BUILD               2 
 
#define VER_FILE_DESCRIPTION_STR    ENDPOINT_NAME " Credential Provider for Windows logon"
#define VER_FILE_VERSION            VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION, VERSION_BUILD
#define VER_FILE_VERSION_STR        STRINGIZE(VERSION_MAJOR)        \
                                    "." STRINGIZE(VERSION_MINOR)    \
                                    "." STRINGIZE(VERSION_REVISION) \
                                    "." STRINGIZE(VERSION_BUILD)    \
 
#define VER_PRODUCTNAME_STR         ENDPOINT_NAME "CredentialProvider"
#define VER_PRODUCT_VERSION         VER_FILE_VERSION
#define VER_PRODUCT_VERSION_STR     VER_FILE_VERSION_STR
#define VER_ORIGINAL_FILENAME_STR   VER_PRODUCTNAME_STR ".dll"
#define VER_INTERNAL_NAME_STR       VER_ORIGINAL_FILENAME_STR
#define VER_COPYRIGHT_STR           "Copyright (C) 2018 NetKnights, 2016 Last Squirrel IT"

#ifndef  VOS_NT_WINDOWS32
#define  VOS_NT_WINDOWS32           0x00040004L
#endif

#ifndef  VFT_APP
#define  VFT_APP                    0x00000001L
#endif
 
#ifdef _DEBUG
  #define VER_VER_DEBUG             VS_FF_DEBUG
#else
  #define VER_VER_DEBUG             0
#endif
 
#define VER_FILEOS                  VOS_NT_WINDOWS32
#define VER_FILEFLAGS               VER_VER_DEBUG
#define VER_FILETYPE                VFT_APP

#endif
