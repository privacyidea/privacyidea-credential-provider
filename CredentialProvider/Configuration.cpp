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
#include <sstream>

using namespace std;

typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

WindowsInfo GetOSVersion() {
	HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
	if (!hMod) return { 0, 0, 0, false, "Error" };

	RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
	if (!fxPtr) return { 0, 0, 0, false, "Error" };

	RTL_OSVERSIONINFOEXW rovi = { 0 };
	rovi.dwOSVersionInfoSize = sizeof(rovi);

	if (fxPtr((PRTL_OSVERSIONINFOW)&rovi) != 0x00000000) { // STATUS_SUCCESS
		return { 0, 0, 0, false, "Error" };
	}

	WindowsInfo info;
	info.major = rovi.dwMajorVersion;
	info.minor = rovi.dwMinorVersion;
	info.build = rovi.dwBuildNumber;

	// VER_NT_WORKSTATION (1) is Client, others are Server/DC
	info.isServer = (rovi.wProductType != VER_NT_WORKSTATION);

	std::stringstream ss;

	if (info.major == 10) {
		if (info.isServer) {
			// Server Mapping based on Build Number
			if (info.build >= 26100) ss << "Windows Server 2025";
			else if (info.build >= 20348) ss << "Windows Server 2022";
			else if (info.build >= 17763) ss << "Windows Server 2019";
			else if (info.build >= 14393) ss << "Windows Server 2016";
			else ss << "Windows Server (Old/Unknown)";
		}
		else {
			// Client Mapping
			if (info.build >= 22000) ss << "Windows 11";
			else ss << "Windows 10";
		}
	}
	else {
		// Fallback for older/newer unknown versions
		ss << "Windows " << info.major << "." << info.minor;
	}

	info.versionString = ss.str();
	return info;
}

std::string WindowsInfoToString(const WindowsInfo& info) {
	std::stringstream ss;
	ss << info.versionString
		<< " (Version " << info.major << "." << info.minor << "." << info.build << ")"
		<< (info.isServer ? " [Server]" : " [Workstation]");
	return ss.str();
}

void Configuration::Load()
{
	RegistryReader rr(CONFIG_REGISTRY_PATH);

	// Connection settings
	piconfig.hostname = rr.GetWString(L"hostname");
	wstring tmp = rr.GetWString(L"path");
	piconfig.path = (tmp == L"/path/to/pi" ? L"" : tmp);
	piconfig.port = rr.GetInt(L"custom_port");
	PIDebug("loading port: " + to_string(piconfig.port));
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
	
	// Offline
	offlineTreshold = rr.GetInt(L"offline_threshold");
	offlineShowInfo = rr.GetBool(L"offline_show_info");
	piconfig.offlineExpirationDays = rr.GetInt(L"offline_expiration_days");
	piconfig.offlineDeleteAfterDays = rr.GetInt(L"offline_delete_after_days");
	piconfig.offlineFilePath = rr.GetWString(L"offline_file");
	piconfig.offlineTryWindow = rr.GetInt(L"offline_try_window");
	checkAllOfflineCredentials = rr.GetBool(L"check_all_offline_credentials");
	
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
	webAuthnOfflineSecondStep = rr.GetBool(L"webauthn_offline_second_step");
	webAuthnOfflinePreferred = rr.GetBool(L"webauthn_offline_preferred");
	webAuthnOfflineHideFirstStep = rr.GetBool(L"webauthn_offline_hide_first_step");
	disablePasskey = rr.GetBool(L"disable_passkey");
	trustedRPIDs = rr.GetMultiSZ(L"trusted_rpids");
	// invert name and logic for explicit disable
	useWindowsHelloForCredUI = !rr.GetBool(L"disable_windows_hello_for_credui");
	
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

	// Autologon
	autoLogonUsername = rr.GetWString(L"autologon_username");
	autoLogonDomain = rr.GetWString(L"autologon_domain");
	autoLogonPassword = rr.GetWString(L"autologon_password");

	windowsVersion = GetOSVersion();
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
	PIDebug("---------------------------------");
	PIDebug("CP Version: " + string(VER_FILE_VERSION_STR));
	PIDebug("Windows Version: " + WindowsInfoToString(windowsVersion));
	PIDebug("--------- Configuration ---------");
	PIDebug(L"Hostname: " + piconfig.hostname);
	PIDebug("Port: " + to_string(piconfig.port));
	PrintIfStringNotEmpty(L"Path", piconfig.path);

	PrintIfIntIsNotNull("Resolve timeout", piconfig.resolveTimeout);
	PrintIfIntIsNotNull("Connect timeout", piconfig.connectTimeout);
	PrintIfIntIsNotNull("Send timeout", piconfig.sendTimeout);
	PrintIfIntIsNotNull("Receive timeout", piconfig.receiveTimeout);

	// Recovery
	PrintIfStringNotEmpty(L"Fallback Hostname", piconfig.fallbackHostname);
	PrintIfStringNotEmpty(L"Fallback Path", piconfig.fallbackPath);
	PrintIfIntIsNotNull("Fallback Port", piconfig.fallbackPort);

	PrintIfStringNotEmpty(L"Locales Path", localesPath);

	PrintIfIntIsNotNull("Hide domain name", hideDomainName);
	PrintIfIntIsNotNull("Hide full name", hideFullName);
	PrintIfIntIsNotNull("SSL ignore unknown CA", piconfig.ignoreUnknownCA);
	PrintIfIntIsNotNull("SSL ignore invalid CN", piconfig.ignoreInvalidCN);
	PrintIfIntIsNotNull("Send empty password", twoStepSendEmptyPassword);
	PrintIfIntIsNotNull("Send domain password", twoStepSendPassword);
	PrintIfIntIsNotNull("Debug Log", debugLog);
	PrintIfIntIsNotNull("Log sensitive data", piconfig.logPasswords);
	PrintIfIntIsNotNull("No default", noDefault);
	PrintIfIntIsNotNull("Show domain hint", showDomainHint);
	PrintIfIntIsNotNull("Prefill username", prefillUsername);
	PrintIfIntIsNotNull("Show reset link", showResetLink);
	
	// FIDO / WebAuthn
	PrintIfIntIsNotNull("WebAuthn preferred", webAuthnPreferred);
	PrintIfIntIsNotNull("WebAuthn offline no PIN", webAuthnOfflineNoPIN);
	PrintIfIntIsNotNull("WebAuthn offline second step", webAuthnOfflineSecondStep);
	PrintIfIntIsNotNull("WebAuthn offline preferred", webAuthnOfflinePreferred);
	PrintIfIntIsNotNull("WebAuthn offline hide first step", webAuthnOfflineHideFirstStep);
	PrintIfIntIsNotNull("Disable passkey", disablePasskey);
	if (!trustedRPIDs.empty())
	{
		PIDebug(L"Trusted RPIDs: " + Convert::JoinW(trustedRPIDs, L", "));
	}
	PIDebug("useWindowsHelloForCredUI: " + string(useWindowsHelloForCredUI ? "true" : "false"));
	// Offline
	PrintIfStringNotEmpty(L"Offline file path", piconfig.offlineFilePath);
	PrintIfIntIsNotNull("Offline try window", piconfig.offlineTryWindow);
	PrintIfIntIsNotValue("Offline refill threshold", offlineTreshold, 10);
	PrintIfIntIsNotNull("Check all offline credentials", checkAllOfflineCredentials);
	PrintIfIntIsNotNull("Offline show info", offlineShowInfo);
	PrintIfIntIsNotNull("Offline expiration days", piconfig.offlineExpirationDays);
	PrintIfIntIsNotNull("Offline delete after days", piconfig.offlineDeleteAfterDays);
	PrintIfIntIsNotNull("OTP fail return to first step", otpFailReturnToFirstStep);
	PrintIfIntIsNotNull("Username+Password Mode", usernamePassword);

	PrintIfIntIsNotNull("Send UPN", piconfig.sendUPN);
	PrintIfStringNotEmpty(L"Bitmap path", bitmapPath);
	
	
	PrintIfStringNotEmpty(L"Default realm", piconfig.defaultRealm);
	PrintIfIntIsNotNull("Hide first step response error", hideFirstStepResponseError);

	PIDebug("Language: " + language);
	PIDebug("Accept-Language: " + piconfig.acceptLanguage);

	PrintIfIntIsNotNull("Is remote session", isRemoteSession);
	PrintIfStringNotEmpty(L"Excluded account", excludedAccount);
	PrintIfStringNotEmpty(L"Excluded group", excludedGroup);
	PrintIfStringNotEmpty(L"Excluded group NetBIOS address", exludedGroupNetBIOSaddress);

	// AutoLogon
	PrintIfStringNotEmpty(L"AutoLogon Username", autoLogonUsername);
	PrintIfStringNotEmpty(L"AutoLogon Domain", autoLogonDomain);
	// We do NOT log the AutoLogon Password for security reasons

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

	PIDebug("---------------------------------");
}
