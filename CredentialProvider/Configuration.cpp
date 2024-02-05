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
#include "Convert.h"

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

	otpFailureText = rr.GetWStringRegistry(L"otp_fail_text");

	prefillUsername = rr.GetBoolRegistry(L"prefill_username");
	showResetLink = rr.GetBoolRegistry(L"enable_reset");
	resetLinkText = rr.GetWStringRegistry(L"reset_link_text");
	offlineTreshold = rr.GetIntRegistry(L"offline_threshold");
	offlineShowInfo = rr.GetBoolRegistry(L"offline_show_info");
	
	// Config for PrivacyIDEA
	piconfig.hostname = rr.GetWStringRegistry(L"hostname");
	// Check if the path contains the placeholder, if so set path to empty string
	tmp = rr.GetWStringRegistry(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);

	piconfig.ignoreUnknownCA = rr.GetBoolRegistry(L"ssl_ignore_unknown_ca");
	piconfig.ignoreInvalidCN = rr.GetBoolRegistry(L"ssl_ignore_invalid_cn");
	auto version = string(VER_FILE_VERSION_STR);
	piconfig.userAgent = L"privacyidea-cp/" + Convert::ToWString(version);
	if (!rr.GetBoolRegistry(L"user_agent_hide_computer_name"))
	{
		piconfig.userAgent += L" Windows/" + Utilities::ComputerName();
	}

	piconfig.customPort = rr.GetIntRegistry(L"custom_port");
	piconfig.offlineFilePath = rr.GetWStringRegistry(L"offline_file");
	piconfig.offlineTryWindow = rr.GetIntRegistry(L"offline_try_window");
	piconfig.sendUPN = rr.GetBoolRegistry(L"send_upn");
	piconfig.resolveTimeout = rr.GetIntRegistry(L"resolve_timeout");
	piconfig.connectTimeout = rr.GetIntRegistry(L"connect_timeout");
	piconfig.sendTimeout = rr.GetIntRegistry(L"send_timeout");
	piconfig.receiveTimeout = rr.GetIntRegistry(L"receive_timeout");

	// format domain\username or computername\username
	excludedAccount = rr.GetWStringRegistry(L"excluded_account");

	// Realm Mapping
	piconfig.defaultRealm = rr.GetWStringRegistry(L"default_realm");

	if (!rr.GetAllEntries(REALM_MAPPING_REGISTRY_PATH, piconfig.realmMap))
	{
		piconfig.realmMap.clear();
	}

	useOtpLinkText = rr.GetWStringRegistry(L"use_otp_link_text");

	// WebAuthn
	webAuthnLinkText = rr.GetWStringRegistry(L"webauthn_link_text");
	webAuthnPreferred = rr.GetBoolRegistry(L"webauthn_preferred");
	webAuthnPinHint = rr.GetWStringRegistry(L"webauthn_pin_hint");

	// Validate that only one of hideDomainName OR hideFullName is active
	// In the installer it is exclusive but could be changed in the registry
	if (hideDomainName && hideFullName)
	{
		hideDomainName = false;
	}
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

void PrintIfIntIsNotValue(string message, int value, int comparable)
{
	if (value != comparable)
	{
		PIDebug(message + ": " + to_string(value));
	}
}

void PrintIfIntIsNotNull(string message, int value)
{
	PrintIfIntIsNotValue(message, value, 0);
}

void PrintIfStringNotEmpty(wstring message, wstring value)
{
	if (!value.empty())
	{
		PIDebug(message + L": " + value);
	}
}

void Configuration::LogConfig()
{
	PIDebug("-----------------------------");
	PIDebug("CP Version: " + string(VER_FILE_VERSION_STR));
	PIDebug(L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr));
	PIDebug("------- Configuration -------");
	PIDebug(L"Hostname: " + piconfig.hostname);
	PrintIfStringNotEmpty(L"Path", piconfig.path);
	PrintIfIntIsNotNull("Custom Port", piconfig.customPort);

	PrintIfIntIsNotNull("Resolve timeout", piconfig.resolveTimeout);
	PrintIfIntIsNotNull("Connect timeout", piconfig.connectTimeout);
	PrintIfIntIsNotNull("Send timeout", piconfig.sendTimeout);
	PrintIfIntIsNotNull("Receive timeout", piconfig.receiveTimeout);

	PrintIfStringNotEmpty(L"Login text", loginText);
	PrintIfStringNotEmpty(L"OTP field text", otpFieldText);
	PrintIfStringNotEmpty(L"OTP failure text", otpFailureText);

	PIDebug("Hide domain/full name: " + Convert::ToString(hideDomainName) + "/" + Convert::ToString(hideFullName));
	PIDebug("SSL ignore unknown CA/invalid CN: " + Convert::ToString(piconfig.ignoreUnknownCA) + "/" + Convert::ToString(piconfig.ignoreInvalidCN));

	PIDebug("2step enabled/send empty/domain password: " + Convert::ToString(twoStepHideOTP)
		+ "/" + Convert::ToString(twoStepSendEmptyPassword) + "/" + Convert::ToString(twoStepSendPassword));
	PIDebug("Debug Log: " + Convert::ToString(debugLog));
	PIDebug("Log sensitive data: " + Convert::ToString(piconfig.logPasswords));
	PIDebug("No default: " + Convert::ToString(noDefault));
	PIDebug("Show domain hint: " + Convert::ToString(showDomainHint));
	PrintIfIntIsNotNull("Send UPN", piconfig.sendUPN);
	PrintIfStringNotEmpty(L"Bitmap path", bitmapPath);
	PrintIfStringNotEmpty(L"Offline file path", piconfig.offlineFilePath);
	PrintIfIntIsNotNull("Offline try window", piconfig.offlineTryWindow);
	PrintIfIntIsNotValue("Offline refill threshold", offlineTreshold, 10);
	PrintIfStringNotEmpty(L"Default realm", piconfig.defaultRealm);

	if (piconfig.realmMap.size() > 0)
	{
		wstring tmp;
		for (const auto& item : piconfig.realmMap)
		{
			tmp += item.first + L"=" + item.second + L", ";
		}
		PIDebug("Realm mapping:");
		PIDebug(tmp.substr(0, tmp.size() - 2).c_str());
	}

	PIDebug("-----------------------------");
}

bool Configuration::IsSecondStep() const noexcept
{
	return scenario == SCENARIO::SECOND_STEP || scenario > SCENARIO::SECURITY_KEY_ANY;
}
