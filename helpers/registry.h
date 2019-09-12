#ifndef _REGISTRY_H
#define _REGISTRY_H
#pragma once

#include "windows.h"
#include <winreg.h>
#include <stdio.h>

#include "../versioning/version.h"

//#if !defined(_WIN64)
	#define REGISTRY_BASE_KEY "SOFTWARE\\Netknights GmbH\\"ENDPOINT_NAME"-CP"
//#else
//	#define REGISTRY_BASE_KEY L"SOFTWARE\\Wow6432Node\\privacyIDEA\\DUMMY-CP"
//#endif


enum CONF_VALUE
{
	CONF_HOSTNAME = 0,
	CONF_LOGIN_TEXT = 1,
	CONF_OTP_TEXT = 2,

	CONF_V1_BITMAP_PATH = 3,
	CONF_V2_BITMAP_PATH = 4,
	
	CONF_TWO_STEP_HIDE_OTP = 5,
	CONF_TWO_STEP_SEND_PASSWORD = 6,

	CONF_SSL_IGNORE_UNKNOWN_CA = 7,
	CONF_SSL_IGNORE_INVALID_CN = 8,

	CONF_HIDE_FULLNAME = 9,
	CONF_HIDE_DOMAINNAME = 10,
	CONF_RELEASE_LOG = 11,
	CONF_PATH = 12,
	CONF_CUSTOM_PORT = 13,
	CONF_TWO_STEP_SEND_EMPTY_PASSWORD = 14,
	CONF_LOG_SENSITIVE = 15,
	CONF_NO_DEFAULT = 16,
	CONF_HIDE_OTP_SLEEP_S = 17,	


	CONF_NUM_VALUES = 18 // LAST
};

static const LPCSTR s_CONF_VALUES[] =
{
	"hostname", //0
	"login_text", // 1 
	"otp_text", // 2

	"v1_bitmap_path", // 3
	"v2_bitmap_path", // 4

	"two_step_hide_otp", // 5 
	"two_step_send_password", // 6

	"ssl_ignore_unknown_ca", // 7
	"ssl_ignore_invalid_cn", // 8

	"hide_fullname", // 9
	"hide_domainname", // 10

	"release_log", // 11
	"path", // 12
	"custom_port", // 13
	"two_step_send_empty_password", // 14
	"log_sensitive", // 15

	"no_default" // 16
	"sleep" // 17
};

DWORD readRegistryValueString(__in LPCSTR value, __in LPCSTR key, __in int buffer_size, __deref_out_opt char* data);
DWORD readRegistryValueString( __in CONF_VALUE conf_value, __in int buffer_size, __deref_out_opt char* data);

DWORD readRegistryValueInteger(__in LPCSTR value, __in LPCSTR key, __deref_out_opt int* data);
DWORD readRegistryValueInteger( __in CONF_VALUE conf_value, __deref_out_opt int* data );

DWORD readRegistryValueBinary(__in LPCSTR value, __in LPCSTR key, __in int buffer_size, __deref_out_opt unsigned char* data);

DWORD writeRegistryValueString(__in LPCSTR value, __in LPCSTR key, __in char* data, __in int buffer_size);
DWORD writeRegistryValueString( __in CONF_VALUE conf_value, __in char* data, __in int buffer_size);

DWORD writeRegistryValueInteger(__in LPCSTR value, __in LPCSTR key, __in int data);
DWORD writeRegistryValueInteger( __in CONF_VALUE conf_value, __in int data );

DWORD writeRegistryValueBinary(__in LPCSTR value, __in LPCSTR key, __in unsigned char* data, __in int buffer_size);

#endif
