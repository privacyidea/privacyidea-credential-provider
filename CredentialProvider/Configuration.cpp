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
#include "RegistryReader.h"

using namespace std;

Configuration::Configuration()
{
	RegistryReader rr(registryPath);

	// Credential Provider specific config
	bitmapPath = rr.getRegistry(L"v1_bitmap_path");
	hideDomainName = rr.getBoolRegistry(L"hide_domainname");
	hideFullName = rr.getBoolRegistry(L"hide_fullname");
	hide_otp_sleep_s = rr.getIntRegistry(L"hide_otp_sleep_s");

	twoStepHideOTP = rr.getBoolRegistry(L"two_step_hide_otp");
	twoStepSendEmptyPassword = rr.getBoolRegistry(L"two_step_send_empty_password");
	twoStepSendPassword = rr.getBoolRegistry(L"two_step_send_password");

	piconfig.logPasswords = rr.getBoolRegistry(L"log_sensitive");
	releaseLog = rr.getBoolRegistry(L"release_log");

	showDomainHint = rr.getBoolRegistry(L"show_domain_hint");
	// Custom field texts: check if set, otherwise use defaults (from header)
	wstring tmp = rr.getRegistry(L"login_text");
	loginText = tmp.empty() ? L"privacyIDEA Login" : tmp;
	tmp = rr.getRegistry(L"otp_text");
	otpFieldText = tmp.empty() ? L"One-Time Password" : tmp;

	tmp = rr.getRegistry(L"otp_fail_text");
	defaultOTPFailureText = tmp.empty() ? defaultOTPFailureText : tmp;

	tmp = rr.getRegistry(L"default_otp_text");
	defaultOTPText = tmp.empty() ? defaultOTPText : tmp;

	// Config for PrivacyIDEA
	piconfig.hostname = rr.getRegistry(L"hostname");
	// Check if the path contains the placeholder, if so replace with nothing
	tmp = rr.getRegistry(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);

	piconfig.ignoreUnknownCA = rr.getBoolRegistry(L"ssl_ignore_unknown_ca");
	piconfig.ignoreInvalidCN = rr.getBoolRegistry(L"ssl_ignore_invalid_cn");
	piconfig.customPort = rr.getIntRegistry(L"custom_port");
	piconfig.offlineFilePath = rr.getRegistry(L"offline_file");
	piconfig.offlineTryWindow = rr.getIntRegistry(L"offline_try_window");

	// Realm Mapping
	piconfig.defaultRealm = rr.getRegistry(L"default_realm");

	map<wstring, wstring> realmMap = map<wstring, wstring>();

	if (!rr.getAll(registryRealmPath, realmMap))
	{
		//DebugPrint("No realm mapping found!");
		realmMap.clear();
	}

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

// for printing
wstring b2ws(bool b) {
	return b ? wstring(L"true") : wstring(L"false");
}

void Configuration::printConfiguration()
{
	DebugPrint("-----------------------------");
	string version(VER_FILE_VERSION_STR);
	string stmp = "CP Version: " + version;
	DebugPrint(stmp.c_str());
	wstring tmp = L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr);
	DebugPrint(tmp.c_str());
	DebugPrint("------- Configuration -------");
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
	tmp = L"OTP failure text: " + defaultOTPFailureText;
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
	tmp = L"Log sensitive data: " + b2ws(piconfig.logPasswords);
	DebugPrint(tmp.c_str());
	tmp = L"No default: " + b2ws(noDefault);
	DebugPrint(tmp.c_str());
	tmp = L"Show domain hint: " + b2ws(showDomainHint);
	DebugPrint(tmp.c_str());
	tmp = L"Bitmap path: " + bitmapPath;
	DebugPrint(tmp.c_str());
	tmp = L"Offline file path: " + piconfig.offlineFilePath;
	DebugPrint(tmp.c_str());
	tmp = L"Offline try window: " + to_wstring(piconfig.offlineTryWindow);
	DebugPrint(tmp.c_str());
	tmp = L"Default realm: " + piconfig.defaultRealm;
	DebugPrint(tmp.c_str());
	tmp = L"";
	for (const auto& item : piconfig.realmMap)
	{
		tmp += item.first + L"=" + item.second + L", ";
	}
	DebugPrint("Realm mapping:");
	DebugPrint(tmp.substr(0, tmp.size() - 2).c_str());

	DebugPrint("-----------------------------");
}
