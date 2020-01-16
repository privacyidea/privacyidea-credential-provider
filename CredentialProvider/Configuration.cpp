/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
** Author: Nils Behlen
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

#include "Configuration.h"
#include "Utilities.h"
#include "version.h"
#include "Logger.h"
#include <Windows.h>
#include <iostream>
#include <tchar.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 1024

using namespace std;

Configuration::Configuration()
{
	loadRegistry();

	loadMapping();

	// Validate that only one of hideDomainName OR hideFullName is active
	// In the installer it is exclusive but could be changed in the registry
	if (hideDomainName && hideFullName)
	{
		hideDomainName = false;
	}
	// Validate 2Step
	if (twoStepSendEmptyPassword || twoStepSendPassword)
	{
		twoStepHideOTP = true;
	}
	if (twoStepSendEmptyPassword && twoStepSendPassword)
	{
		twoStepSendEmptyPassword = false;
	}

	// Get the Windows Version, deprecated 
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	winVerMajor = info.dwMajorVersion;
	winVerMinor = info.dwMinorVersion;
	winBuildNr = info.dwBuildNumber;
}

bool Configuration::loadRegistry()
{
	// Credential Provider specific config
	bitmapPath = getRegistry(L"v1_bitmap_path");
	loginText = getRegistry(L"login_text");
	otpFieldText = getRegistry(L"otp_text");
	otpFailureText = getRegistry(L"otp_fail_text");

	twoStepHideOTP = getBoolRegistry(L"two_step_hide_otp");
	twoStepSendEmptyPassword = getBoolRegistry(L"two_step_send_empty_password");
	twoStepSendPassword = getBoolRegistry(L"two_step_send_password");

	releaseLog = getBoolRegistry(L"release_log");
	logSensitive = getBoolRegistry(L"log_sensitive");

	hideDomainName = getBoolRegistry(L"hide_domainname");
	hideFullName = getBoolRegistry(L"hide_fullname");
	hide_otp_sleep_s = getIntRegistry(L"hide_otp_sleep_s");


	// Config for PrivacyIDEA
	piconfig.hostname = getRegistry(L"hostname");
	// Check if the path contains the placeholder, if so replace with nothing
	auto tmp = getRegistry(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);

	piconfig.ignoreUnknownCA = getBoolRegistry(L"ssl_ignore_unknown_ca");
	piconfig.ignoreInvalidCN = getBoolRegistry(L"ssl_ignore_invalid_cn");
	piconfig.customPort = getIntRegistry(L"custom_port");

	return true;
}

bool Configuration::loadMapping()
{
	piconfig.defaultRealm = getRegistry(L"default_realm");

	// Open handle to realm-mapping key
	HKEY hKey = nullptr;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\realm-mapping"),
		0,
		KEY_READ,
		&hKey) != ERROR_SUCCESS)
	{
		return false;
	}

	//WCHAR    achKey[MAX_KEY_LENGTH];		// buffer for subkey name
	//DWORD    cbName;						// size of name string 
	WCHAR    achClass[MAX_PATH] = TEXT(""); // buffer for class name 
	DWORD    cchClassName = MAX_PATH;		// size of class string 
	DWORD    cSubKeys = 0;					// number of subkeys 
	DWORD    cbMaxSubKey;					// longest subkey size 
	DWORD    cchMaxClass;					// longest class string 
	DWORD    cValues;						// number of values for key 
	DWORD    cchMaxValue;					// longest value name 
	DWORD    cbMaxValueData;				// longest value data 
	DWORD    cbSecurityDescriptor;			// size of security descriptor 
	FILETIME ftLastWriteTime;				// last write time 

	DWORD i, retCode;

	WCHAR achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	if (cValues)
	{
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValueW(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);
			if (retCode == ERROR_SUCCESS)
			{
				wstring value(achValue);
				// Get the data for the value
				const DWORD SIZE = 1024;
				TCHAR szData[SIZE] = _T("");
				DWORD dwValue = SIZE;
				DWORD dwType = 0;
				DWORD dwRet = 0;

				dwRet = RegQueryValueEx(
					hKey,
					value.c_str(),
					NULL,
					&dwType,
					(LPBYTE)&szData,
					&dwValue);
				if (dwRet == ERROR_SUCCESS)
				{
					if (dwType == REG_SZ)
					{
						wstring data(szData);
						piconfig.realmMap.try_emplace(value, data);
					}
				}
			}
		}
	}
	RegCloseKey(hKey);

	return true;
}

bool Configuration::getBoolRegistry(wstring name)
{
	// Non existing keys evaluate to false.
	return getRegistry(name) == L"1";
}

int Configuration::getIntRegistry(wstring name)
{
	return _wtoi(getRegistry(name).c_str());
}

wstring Configuration::getRegistry(wstring name)
{
	DWORD dwRet = NULL;
	HKEY hKey = nullptr;

	dwRet = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		_T("SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP"),
		NULL,
		KEY_QUERY_VALUE,
		&hKey);
	if (dwRet != ERROR_SUCCESS)
	{
		return L"";
	}

	const DWORD SIZE = 1024;
	TCHAR szValue[SIZE] = _T("");
	DWORD dwValue = SIZE;
	DWORD dwType = 0;
	dwRet = RegQueryValueEx(
		hKey,
		name.c_str(),
		NULL,
		&dwType,
		(LPBYTE)&szValue,
		&dwValue);
	if (dwRet != ERROR_SUCCESS)
	{
		return L"";
	}

	if (dwType != REG_SZ)
	{
		return L"";
	}
	RegCloseKey(hKey);
	hKey = NULL;
	return wstring(szValue);
}

wstring b2ws(bool b) {
	return b ? L"true" : L"false";
}

void Configuration::printConfiguration()
{
	string version(VER_FILE_VERSION_STR);
	string stmp = "Credential Provider Version: " + version;
	DebugPrint(stmp.c_str());
	wstring tmp = L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr);
	DebugPrint(tmp.c_str());
	DebugPrint("----- Configuration -----");
	tmp = L"Hostname: " + piconfig.hostname;
	DebugPrint(tmp.c_str());
	tmp = L"Path: " + piconfig.path;
	DebugPrint(tmp.c_str());
	tmp = L"Custom port:" + to_wstring(piconfig.customPort);
	DebugPrint(tmp.c_str());
	tmp = L"Login text: " + loginText;
	DebugPrint(tmp.c_str());
	tmp = L"OTP field text: " + otpFieldText;
	DebugPrint(tmp.c_str());
	tmp = L"Hide domain only: " + b2ws(hideDomainName);
	DebugPrint(tmp.c_str());
	tmp = L"Hide full name: " + b2ws(hideFullName);
	DebugPrint(tmp.c_str());
	tmp = L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreUnknownCA);
	DebugPrint(tmp.c_str());
	tmp = L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreInvalidCN);
	DebugPrint(tmp.c_str());
	tmp = L"2step hide OTP: " + b2ws(twoStepHideOTP);
	DebugPrint(tmp.c_str());
	tmp = L"2step send empty PW: " + b2ws(twoStepSendEmptyPassword);
	DebugPrint(tmp.c_str());
	tmp = L"2step send domain PW: " + b2ws(twoStepSendPassword);
	DebugPrint(tmp.c_str());
	tmp = L"Release Log: " + b2ws(releaseLog);
	DebugPrint(tmp.c_str());
	tmp = L"No default: " + b2ws(noDefault);
	DebugPrint(tmp.c_str());
	tmp = L"Bitmap path: " + bitmapPath;
	DebugPrint(tmp.c_str());
}