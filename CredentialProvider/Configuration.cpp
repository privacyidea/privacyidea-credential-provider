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

void Configuration::Load()
{
	RegistryReader rr(CONFIG_REGISTRY_PATH);

	// Credential Provider specific config
	bitmapPath = rr.GetWStringRegistry(L"v1_bitmap_path");
	hideDomainName = rr.GetBoolRegistry(L"hide_domainname");
	hideFullName = rr.GetBoolRegistry(L"hide_fullname");
	noDefault = rr.GetBoolRegistry(L"no_default");
	twoStepHideOTP = rr.GetBoolRegistry(L"two_step_hide_otp");
	twoStepSendEmptyPassword = rr.GetBoolRegistry(L"two_step_send_empty_password");
	twoStepSendPassword = rr.GetBoolRegistry(L"two_step_send_password");

	piconfig.logPasswords = rr.GetBoolRegistry(L"log_sensitive");
	debugLog = rr.GetBoolRegistry(L"debug_log");
#ifdef _DEBUG
	// Always on for debug builds
	debugLog = true;
#endif // _DEBUG

	showDomainHint = rr.GetBoolRegistry(L"show_domain_hint");
	// Custom field texts: check if set, otherwise use defaults (from header)
	wstring tmp = rr.GetWStringRegistry(L"login_text");
	loginText = tmp.empty() ? L"privacyIDEA Login" : tmp;

	otpFieldText = rr.GetWStringRegistry(L"otp_text");

	tmp = rr.GetWStringRegistry(L"otp_fail_text");
	defaultOTPFailureText = tmp.empty() ? Utilities::GetTranslatedText(TEXT_WRONG_OTP) : tmp;

	tmp = rr.GetWStringRegistry(L"otp_hint_text");
	defaultOTPHintText = tmp.empty() ? Utilities::GetTranslatedText(TEXT_DEFAULT_OTP_HINT) : tmp;

	prefillUsername = rr.GetBoolRegistry(L"prefill_username");
	showResetLink = rr.GetBoolRegistry(L"enable_reset");

	// Config for PrivacyIDEA
	piconfig.hostname = rr.GetWStringRegistry(L"hostname");
	// Check if the path contains the placeholder, if so set path to empty string
	tmp = rr.GetWStringRegistry(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);

	piconfig.ignoreUnknownCA = rr.GetBoolRegistry(L"ssl_ignore_unknown_ca");
	piconfig.ignoreInvalidCN = rr.GetBoolRegistry(L"ssl_ignore_invalid_cn");
	piconfig.customPort = rr.GetIntRegistry(L"custom_port");
	piconfig.offlineFilePath = rr.GetWStringRegistry(L"offline_file");
	piconfig.offlineTryWindow = rr.GetIntRegistry(L"offline_try_window");

	piconfig.resolveTimeoutMS = rr.GetIntRegistry(L"resolve_timeout");
	piconfig.connectTimeoutMS = rr.GetIntRegistry(L"connect_timeout");
	piconfig.sendTimeoutMS = rr.GetIntRegistry(L"send_timeout");
	piconfig.receiveTimeoutMS = rr.GetIntRegistry(L"receive_timeout");

	// format domain\username or computername\username
	excludedAccount = rr.GetWStringRegistry(L"excluded_account");

	// Realm Mapping
	piconfig.defaultRealm = rr.GetWStringRegistry(L"default_realm");

	if (!rr.GetAllEntries(REALM_MAPPING_REGISTRY_PATH, piconfig.realmMap))
	{
		piconfig.realmMap.clear();
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
inline wstring b2ws(bool b)
{
	return b ? wstring(L"true") : wstring(L"false");
}

void Configuration::LogConfig()
{
	DebugPrint("-----------------------------");
	DebugPrint("CP Version: " + string(VER_FILE_VERSION_STR));
	DebugPrint(L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr));
	DebugPrint("------- Configuration -------");
	DebugPrint(L"Hostname: " + piconfig.hostname);
	DebugPrint(L"Path: " + piconfig.path);
	DebugPrint(L"Custom port: " + to_wstring(piconfig.customPort));
	DebugPrint(L"Resolve timeout: " + to_wstring(piconfig.resolveTimeoutMS));
	DebugPrint(L"Connect timeout: " + to_wstring(piconfig.connectTimeoutMS));
	DebugPrint(L"Send timeout: " + to_wstring(piconfig.sendTimeoutMS));
	DebugPrint(L"Receive timeout: " + to_wstring(piconfig.receiveTimeoutMS));
	DebugPrint(L"Login text: " + loginText);
	DebugPrint(L"OTP field text: " + otpFieldText);
	DebugPrint(L"OTP failure text: " + defaultOTPFailureText);
	DebugPrint(L"Hide domain only: " + b2ws(hideDomainName));
	DebugPrint(L"Hide full name: " + b2ws(hideFullName));
	DebugPrint(L"SSL ignore unknown CA: " + b2ws(piconfig.ignoreUnknownCA));
	DebugPrint(L"SSL ignore invalid CN: " + b2ws(piconfig.ignoreInvalidCN));
	DebugPrint(L"2step hide OTP: " + b2ws(twoStepHideOTP));
	DebugPrint(L"2step send empty PW: " + b2ws(twoStepSendEmptyPassword));
	DebugPrint(L"2step send domain PW: " + b2ws(twoStepSendPassword));
	DebugPrint(L"Debug Log: " + b2ws(debugLog));
	DebugPrint(L"Log sensitive data: " + b2ws(piconfig.logPasswords));
	DebugPrint(L"No default: " + b2ws(noDefault));
	DebugPrint(L"Show domain hint: " + b2ws(showDomainHint));
	DebugPrint(L"Bitmap path: " + bitmapPath);
	DebugPrint(L"Offline file path: " + piconfig.offlineFilePath);
	DebugPrint(L"Offline try window: " + to_wstring(piconfig.offlineTryWindow));
	DebugPrint(L"Default realm: " + piconfig.defaultRealm);

	wstring tmp;
	for (const auto& item : piconfig.realmMap)
	{
		tmp += item.first + L"=" + item.second + L", ";
	}
	DebugPrint("Realm mapping:");
	DebugPrint(tmp.substr(0, tmp.size() - 2).c_str());

	DebugPrint("-----------------------------");
}