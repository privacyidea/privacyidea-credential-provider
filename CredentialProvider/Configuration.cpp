#include "Configuration.h"
#include "../versioning/version.h"
#include "../CredentialProvider/core/helper.h"
#include <Windows.h>
#include <tchar.h>
#include <iostream>

using namespace std;
auto &config = Configuration::Get();

Configuration::Configuration()
{
	loadConfig();
}

void Configuration::loadConfig() {
	this->bitmapPath = getRegistry(L"v1_bitmap_path");

	this->path = getRegistry(L"path");
	this->hostname = getRegistry(L"hostname");

	this->hideDomainName = getBoolRegistry(L"hide_domainname");
	this->hideFullName = getBoolRegistry(L"hide_fullname");
	this->sslIgnoreCA = getBoolRegistry(L"ssl_ignore_unknown_ca");
	this->sslIgnoreCN = getBoolRegistry(L"ssl_ignore_invalid_cn");
	this->loginText = getRegistry(L"login_text");
	this->otpText = getRegistry(L"otp_text");
	this->twoStepHideOTP = getBoolRegistry(L"two_step_hide_otp");
	this->twoStepSendEmptyPassword = getBoolRegistry(L"two_step_send_empty_password");
	this->twoStepSendPassword = getBoolRegistry(L"two_step_send_password");
	this->releaseLog = getBoolRegistry(L"release_log");
	this->logSensitive = getBoolRegistry(L"log_sensitive");
	this->customPort = _wtoi(getRegistry(L"custom_port").c_str());
	this->hide_otp_sleep_s = _wtoi(getRegistry(L"hide_otp_sleep_s").c_str());

	// Validate that only one of hideDomainName and hideFullName is active
	// In the installer it is exclusive but could be changed in the registry
	if (this->hideDomainName && this->hideFullName) {
		this->hideDomainName = false;
	}
	
	// Get the Windows Version 
	// TODO: Use RtlGetVersion
	OSVERSIONINFOEX info;
	ZeroMemory(&info, sizeof(OSVERSIONINFOEX));
	info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&info);

	this->winVerMajor = info.dwMajorVersion;
	this->winVerMinor = info.dwMinorVersion;
	this->winBuildNr = info.dwBuildNumber;
}

bool Configuration::getBoolRegistry(wstring name) {
	// Non existing keys evaluate to false.
	return getRegistry(name) == L"1";
}

wstring Configuration::getRegistry(wstring name)
{
	DWORD dwRet;
	HKEY hKey;

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

inline const wstring b2ws(bool b) {
	return b ? L"true" : L"false";
}

void Configuration::PrintConfig()
{
	string version(VER_FILE_VERSION_STR);
	wstring tmp = L"Credential Provider Version: " + Helper::s2ws(version);
	DebugPrintLn(tmp.c_str());
	tmp = L"Windows Version: " + to_wstring(config.winVerMajor) + L"." + to_wstring(config.winVerMinor)
		+ L"." + to_wstring(config.winBuildNr);
	DebugPrintLn(tmp.c_str());
	DebugPrintLn("----- Configuration -----");
	tmp = L"Hostname: " + config.hostname;
	DebugPrintLn(tmp.c_str());
	tmp = L"Path: " + config.path;
	DebugPrintLn(tmp.c_str());
	tmp = L"Custom port:" + to_wstring(config.customPort);
	DebugPrintLn(tmp.c_str());
	tmp = L"Login text: " + config.loginText;
	DebugPrintLn(tmp.c_str());
	tmp = L"OTP field text: " + config.otpText;
	DebugPrintLn(tmp.c_str());
	tmp = L"Hide domain only: " + b2ws(config.hideDomainName);
	DebugPrintLn(tmp.c_str());
	tmp = L"Hide full name: " + b2ws(config.hideFullName);
	DebugPrintLn(tmp.c_str());
	tmp = L"SSL ignore invalid CN: " + b2ws(config.sslIgnoreCN);
	DebugPrintLn(tmp.c_str());
	tmp = L"SSL ignore invalid CN: " + b2ws(config.sslIgnoreCN);
	DebugPrintLn(tmp.c_str());
	tmp = L"2step hide OTP: " + b2ws(config.twoStepHideOTP);
	DebugPrintLn(tmp.c_str()); 
	tmp = L"2step send empty PW: " + b2ws(config.twoStepSendEmptyPassword);
	DebugPrintLn(tmp.c_str());
	tmp = L"2step send domain PW: " + b2ws(config.twoStepSendPassword);
	DebugPrintLn(tmp.c_str());
	tmp = L"Release Log: " + b2ws(config.releaseLog);
	DebugPrintLn(tmp.c_str());
	tmp = L"No default: " + b2ws(config.noDefault);
	DebugPrintLn(tmp.c_str());
	tmp = L"Bitmap path: " + config.bitmapPath;
	DebugPrintLn(tmp.c_str());
}
