/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2012 Dominik Pretzsch
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#include "stdafx.h"
#include <Lm.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

UINT __stdcall SanitizeDwordFromRegistry(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "SanitizeDword");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	///
	wchar_t cPropertyName[MAX_PATH];
	wchar_t cPropertyValue[MAX_PATH];

	DWORD dwMaxLen = MAX_PATH;

	// TODO: Support multiple properties (separated by comma)
	MsiGetProperty(hInstall, L"SANITIZE_DWORD", cPropertyName, &dwMaxLen);
	MsiGetProperty(hInstall, cPropertyName, cPropertyValue, &dwMaxLen);

	if (cPropertyValue[0] == '#')
	{
		WcaLog(LOGMSG_STANDARD, "Property %s needs sanitation...", cPropertyName);
		for (unsigned int i = 1; i < dwMaxLen; i++)
		{
			cPropertyValue[i - 1] = cPropertyValue[i];
			cPropertyValue[i] = NULL;
		}
		WcaLog(LOGMSG_STANDARD, "Sanitation done.");
	}

	MsiSetProperty(hInstall, cPropertyName, cPropertyValue);
	///

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}

bool is_user_admin()
{
	WcaLog(LOGMSG_STANDARD, "is_user_admin() START.");
	bool result;
	DWORD rc;
	wchar_t user_name[256];
	USER_INFO_1 *info;
	DWORD size = sizeof(user_name);

	GetUserNameW(user_name, &size);

	rc = NetUserGetInfo(NULL, user_name, 1, (LPBYTE *)&info);
	if (rc != NERR_Success)
		return false;

	result = info->usri1_priv == USER_PRIV_ADMIN;

	NetApiBufferFree(info);
	if (result) {
		WcaLog(LOGMSG_STANDARD, "is_user_admin(). returning true");
	}
	else { WcaLog(LOGMSG_STANDARD, "is_user_admin().returning false"); }
	WcaLog(LOGMSG_STANDARD, "is_user_admin() END.");
	return result;
}

/*
UINT __stdcall CheckAdministratorPrivileges(MSIHANDLE hInstall)
{

	struct Data
	{
		PACL   pACL;
		PSID   psidAdmin;
		HANDLE hToken;
		HANDLE hImpersonationToken;
		PSECURITY_DESCRIPTOR     psdAdmin;
		Data() : pACL(NULL), psidAdmin(NULL), hToken(NULL),
			hImpersonationToken(NULL), psdAdmin(NULL)
		{}
		~Data()
		{
			if (pACL)
				LocalFree(pACL);
			if (psdAdmin)
				LocalFree(psdAdmin);
			if (psidAdmin)
				FreeSid(psidAdmin);
			if (hImpersonationToken)
				CloseHandle(hImpersonationToken);
			if (hToken)
				CloseHandle(hToken);
		}
	} data;
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "CheckAdministratorPrivileges");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "IsUserAdmin() START");
	BOOL   fReturn = FALSE;
	DWORD  dwStatus;
	DWORD  dwAccessMask;
	DWORD  dwAccessDesired;
	DWORD  dwACLSize;
	DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);

	PRIVILEGE_SET   ps;
	GENERIC_MAPPING GenericMapping;
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;

	//const DWORD ACCESS_READ = 1;
	//const DWORD ACCESS_WRITE = 2;

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &data.hToken))
	{
		if (GetLastError() != ERROR_NO_TOKEN)
			WcaLog(LOGMSG_STANDARD, "error other than no token");
			return false;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &data.hToken))
			WcaLog(LOGMSG_STANDARD, "error: openProcessToken");
			return false;
	}

	if (!DuplicateToken(data.hToken, SecurityImpersonation, &data.hImpersonationToken))
		WcaLog(LOGMSG_STANDARD, "no duplicate token");
		return false;

	if (!AllocateAndInitializeSid(&SystemSidAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &data.psidAdmin))
		WcaLog(LOGMSG_STANDARD, "!AllocateAndInitializeSid");
		return false;

	data.psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (data.psdAdmin == NULL)
		WcaLog(LOGMSG_STANDARD, "data.psdAdmin == NULL");
		return false;

	if (!InitializeSecurityDescriptor(data.psdAdmin, SECURITY_DESCRIPTOR_REVISION))
		WcaLog(LOGMSG_STANDARD, "!InitializeSecurityDescriptor");
		return false;

	// Compute size needed for the ACL.
	dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(data.psidAdmin) - sizeof(DWORD);

	data.pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
	if (data.pACL == NULL)
		WcaLog(LOGMSG_STANDARD, "data.pACL == NULL");
		return false;

	if (!InitializeAcl(data.pACL, dwACLSize, ACL_REVISION2))
		WcaLog(LOGMSG_STANDARD, "!InitializeAcl");
		return false;

	dwAccessMask = ACCESS_READ | ACCESS_WRITE;

	if (!AddAccessAllowedAce(data.pACL, ACL_REVISION2, dwAccessMask, data.psidAdmin))
		WcaLog(LOGMSG_STANDARD, "!AddAccessAllowedAce");
		return false;

	if (!SetSecurityDescriptorDacl(data.psdAdmin, TRUE, data.pACL, FALSE))
		WcaLog(LOGMSG_STANDARD, "!SetSecurityDescriptorDacl");
		return false;

	// AccessCheck validates a security descriptor somewhat; set the group
	// and owner so that enough of the security descriptor is filled out
	// to make AccessCheck happy.

	SetSecurityDescriptorGroup(data.psdAdmin, data.psidAdmin, FALSE);
	SetSecurityDescriptorOwner(data.psdAdmin, data.psidAdmin, FALSE);

	if (!IsValidSecurityDescriptor(data.psdAdmin))
		WcaLog(LOGMSG_STANDARD, "invalid security descriptor");
		return false;

	dwAccessDesired = ACCESS_READ;

	GenericMapping.GenericRead = ACCESS_READ;
	GenericMapping.GenericWrite = ACCESS_WRITE;
	GenericMapping.GenericExecute = 0;
	GenericMapping.GenericAll = ACCESS_READ | ACCESS_WRITE;

	if (!AccessCheck(data.psdAdmin, data.hImpersonationToken, dwAccessDesired,
		&GenericMapping, &ps, &dwStructureSize, &dwStatus,
		&fReturn))
	{
		WcaLog(LOGMSG_STANDARD, "access check denied");
		return false;
	}
	WcaLog(LOGMSG_STANDARD, "IsUserAdmin() END");
	MsiSetProperty(hInstall, L"USER_IS_ADMINISTRATOR", fReturn ? L"1" : L"0");
	MsiCloseAllHandles();
	return WcaFinalize(1);

LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	MsiCloseAllHandles();
	return WcaFinalize(er);

}
*/

UINT __stdcall CheckAdministratorPrivileges(MSIHANDLE hInstall)
{
	HRESULT hr = S_OK;
	UINT er = ERROR_SUCCESS;

	hr = WcaInitialize(hInstall, "CheckAdministratorPrivileges");
	ExitOnFailure(hr, "Failed to initialize");

	WcaLog(LOGMSG_STANDARD, "Initialized.");

	///
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	// Initialize SID.
	if (!AllocateAndInitializeSid(&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup))
	{
		// Initializing SID Failed.
		//return false;
		hr = E_FAIL;
		ExitOnFailure(hr, "Initializing SID Failed");
	}
	// Check whether the token is present in admin group.
	BOOL IsInAdminGroup = FALSE;
	if (!CheckTokenMembership(NULL,
		AdministratorsGroup,
		&IsInAdminGroup))
	{
		// Error occurred.
		IsInAdminGroup = FALSE;
	}
	// Free SID and return.
	FreeSid(AdministratorsGroup);
	//return IsInAdminGroup;
	if (!IsInAdminGroup)
		hr = E_FAIL;
	//if (is_user_admin()) { IsInAdminGroup = TRUE; }
	//else { IsInAdminGroup = FALSE; }
	//IsInAdminGroup = IsUserAdmin();
	MsiSetProperty (hInstall, L"USER_IS_ADMINISTRATOR", IsInAdminGroup ? L"1" : L"0");
	///
	if (IsInAdminGroup == TRUE) {
		WcaLog(LOGMSG_STANDARD, "IsInAdminGroup == TRUE");
		MsiSetProperty(hInstall, L"USER_IS_ADMINISTRATOR", L"1");
	}
	else {
		MsiSetProperty(hInstall, L"USER_IS_ADMINISTRATOR", L"0");
		WcaLog(LOGMSG_STANDARD, "IsInAdminGroup == FALSE");
	}
LExit:
	er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
	return WcaFinalize(er);
}


// DllMain - Initialize and cleanup WiX custom action utils.
extern "C" BOOL WINAPI DllMain(
	__in HINSTANCE hInst,
	__in ULONG ulReason,
	__in LPVOID
)
{
	switch (ulReason)
	{
	case DLL_PROCESS_ATTACH:
		WcaGlobalInitialize(hInst);
		break;

	case DLL_PROCESS_DETACH:
		WcaGlobalFinalize();
		break;
	}

	return TRUE;
}
