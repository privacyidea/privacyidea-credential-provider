/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
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

#include <Windows.h>
#include <string>
#include <locale>
#include "Configuration.h"
#include "Utilities.h"
#include "version.h"
#include "Logger.h"
#include "RegistryReader.h"
#include "Convert.h"
#include <Shared.h>
#include <Translator.h>

using namespace std;

void Configuration::Load()
{
	RegistryReader rr(CONFIG_REGISTRY_PATH);

	// Connection settings
	piconfig.hostname = rr.GetWString(L"hostname");
	wstring tmp = rr.GetWString(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);
	piconfig.port = rr.GetInt(L"custom_port");

	piconfig.ignoreUnknownCA = rr.GetBool(L"ssl_ignore_unknown_ca");
	piconfig.ignoreInvalidCN = rr.GetBool(L"ssl_ignore_invalid_cn");

	piconfig.userAgent = L"privacyidea-cp/" + Convert::ToWString(string(VER_FILE_VERSION_STR));
	if (!rr.GetBool(L"user_agent_hide_computer_name"))
	{
		piconfig.userAgent += L" Windows/" + Utilities::ComputerName();
	}

	piconfig.resolveTimeout = rr.GetInt(L"resolve_timeout");
	piconfig.connectTimeout = rr.GetInt(L"connect_timeout");
	piconfig.sendTimeout = rr.GetInt(L"send_timeout");
	piconfig.receiveTimeout = rr.GetInt(L"receive_timeout");

	// Recovery
	piconfig.fallbackHostname = rr.GetWString(L"fallback_hostname");
	piconfig.fallbackPath = rr.GetWString(L"fallback_path");
	piconfig.fallbackPort = rr.GetInt(L"fallback_port");

	excludedAccount = rr.GetWString(L"excluded_account");
	excludedGroup = rr.GetWString(L"excluded_group");
	exludedGroupNetBIOSaddress = rr.GetWString(L"excluded_group_netbios_address");

	// Credential Provider specific config
	bitmapPath = rr.GetWString(L"v1_bitmap_path");
	hideDomainName = rr.GetBool(L"hide_domainname");
	hideFullName = rr.GetBool(L"hide_fullname");
	noDefault = rr.GetBool(L"no_default");
	twoStepSendEmptyPassword = rr.GetBool(L"two_step_send_empty_password");
	twoStepSendPassword = rr.GetBool(L"two_step_send_password");
	usernamePassword = rr.GetBool(L"username_password");

	// Set locales files path from registry
	localesPath = rr.GetWString(L"localesPath");

	debugLog = rr.GetBool(L"debug_log");
#ifdef _DEBUG
	// Always on for debug builds
	debugLog = true;
#endif // _DEBUG
	piconfig.logPasswords = rr.GetBool(L"log_sensitive");

	showDomainHint = rr.GetBool(L"show_domain_hint");

	// Custom field texts: check if set, otherwise use defaults (from header)

	hideFirstStepResponseError = rr.GetBool(L"hide_first_step_response_error");

	prefillUsername = rr.GetBool(L"prefill_username");
	showResetLink = rr.GetBool(L"enable_reset");
	offlineTreshold = rr.GetInt(L"offline_threshold");
	offlineShowInfo = rr.GetBool(L"offline_show_info");
	creduiNoImage = rr.GetBool(L"credui_no_image");

	piconfig.offlineFilePath = rr.GetWString(L"offline_file");
	piconfig.offlineTryWindow = rr.GetInt(L"offline_try_window");
	piconfig.sendUPN = rr.GetBool(L"send_upn");

	piconfig.acceptLanguage = ValidateAcceptLanguage(rr.GetWString(L"header_accept_language"));

	language = Convert::ToString(rr.GetWString(L"language"));
	if (!language.empty())
	{
		if (language.size() != 2)
		{
			PIError("Configured language code is invalid: " + language + ", only 2 characters allowed, like 'en' or 'de'. Using language from system.");
		}
		else
		{
			Translator::GetInstance().SetLanguage(language);
		}
	}

	// Realm Mapping
	piconfig.defaultRealm = rr.GetWString(L"default_realm");

	if (!rr.GetAll(REALM_MAPPING_REGISTRY_PATH, piconfig.realmMap))
	{
		piconfig.realmMap.clear();
	}

	otpFailReturnToFirstStep = rr.GetBool(L"otp_fail_return_to_first_step");

	// FIDO / WebAuthn
	webAuthnPreferred = rr.GetBool(L"webauthn_preferred");
	webAuthnOfflineNoPIN = rr.GetBool(L"webauthn_offline_no_pin");
	disablePasskey = rr.GetBool(L"disable_passkey");

	// Validate that only one of hideDomainName OR hideFullName is active
	// In the installer it is exclusive but could be changed in the registry
	if (hideDomainName && hideFullName)
	{
		hideDomainName = false;
	}
	if (twoStepSendEmptyPassword && twoStepSendPassword)
	{
		twoStepSendEmptyPassword = false;
	}

	isRemoteSession = Shared::IsCurrentSessionRemote();

	// Get the Windows Version, deprecated 
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	winVerMajor = info.dwMajorVersion;
	winVerMinor = info.dwMinorVersion;
	winBuildNr = info.dwBuildNumber;
}

std::string Configuration::ValidateAcceptLanguage(std::wstring configEntry)
{
	if (configEntry.empty() || configEntry == L"system")
	{
		// Get the ISO 639 language name (e.g., "en")
		wchar_t wlanguage[9] = { 0 };
		if (GetLocaleInfoEx(LOCALE_NAME_USER_DEFAULT, LOCALE_SISO639LANGNAME, wlanguage, sizeof(wlanguage) / sizeof(wchar_t)) == 0)
		{
			PIError("Unable to get ISO 639 language name, using default en-US.");
			return "en-US";
		}

		// Get the ISO 3166 country/region name (e.g., "US")
		wchar_t country[9] = { 0 };
		if (GetLocaleInfoEx(LOCALE_NAME_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, country, sizeof(country) / sizeof(wchar_t)) == 0)
		{
			PIError("Unable to get ISO 3166 country name, using default en-US.");
			return "en-US";
		}

		std::wstring wresult = wlanguage;
		PIDebug("Language result: " + Convert::ToString(wresult));
		wresult += L"-";
		for (wchar_t& c : wresult) c = towlower(c);
		for (wchar_t& c : country) c = towlower(c);
		wresult += country;
		return Convert::ToString(wresult);
	}
	else
	{
		// very simple format check
		auto str = Convert::ToString(configEntry);
		if (str.length() != 5)
		{
			PIError("Configured Accept-Language format is invalid: " + str + ". Using default en-US.");
			return "en-US";
		}
		else if (std::isalpha(str[0]) && std::isalpha(str[1]) && str[2] == '-' && std::isalpha(str[3]) && std::isalpha(str[4]))
		{
			return str;
		}
		else
		{
			PIError("Configured Accept-Language format is invalid: " + str + ". Using default en-US.");
			return "en-US";
		}
	}
}

static void PrintIfIntIsNotValue(string message, int value, int comparable)
{
	if (value != comparable)
	{
		PIDebug(message + ": " + to_string(value));
	}
}

static void PrintIfIntIsNotNull(string message, int value)
{
	PrintIfIntIsNotValue(message, value, 0);
}

static void PrintIfStringNotEmpty(wstring message, wstring value)
{
	if (!value.empty())
	{
		PIDebug(message + L": " + value);
	}
}

void Configuration::LogConfig()
{
	// TODO update
	PIDebug("-----------------------------");
	PIDebug("CP Version: " + string(VER_FILE_VERSION_STR));
	PIDebug(L"Windows Version: " + to_wstring(winVerMajor) + L"." + to_wstring(winVerMinor)
		+ L"." + to_wstring(winBuildNr));
	PIDebug("------- Configuration -------");
	PIDebug(L"Hostname: " + piconfig.hostname);
	PrintIfStringNotEmpty(L"Path", piconfig.path);
	PrintIfIntIsNotNull("Custom Port", piconfig.port);

	PrintIfIntIsNotNull("Resolve timeout", piconfig.resolveTimeout);
	PrintIfIntIsNotNull("Connect timeout", piconfig.connectTimeout);
	PrintIfIntIsNotNull("Send timeout", piconfig.sendTimeout);
	PrintIfIntIsNotNull("Receive timeout", piconfig.receiveTimeout);

	PrintIfStringNotEmpty(L"Locales Path", localesPath);

	PIDebug("Hide domain/full name: " + Convert::ToString(hideDomainName) + "/" + Convert::ToString(hideFullName));
	PIDebug("SSL ignore unknown CA/invalid CN: " + Convert::ToString(piconfig.ignoreUnknownCA) + "/" + Convert::ToString(piconfig.ignoreInvalidCN));

	PIDebug("send empty/domain password: " + Convert::ToString(twoStepSendEmptyPassword) + "/" + Convert::ToString(twoStepSendPassword));
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
	PIDebug("hideFirstStepResponseError: " + Convert::ToString(hideFirstStepResponseError));
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
