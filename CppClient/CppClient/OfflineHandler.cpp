/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2019 NetKnights GmbH
** Author:		Nils Behlen
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

#include "OfflineHandler.h"
#include "JsonParser.h"
#include "Convert.h"
#include <iostream>
#include <fstream>
#include <atlenc.h>
#include <algorithm>

#pragma comment (lib, "bcrypt.lib")

using namespace std;

std::wstring getErrorText(DWORD err)
{
	LPWSTR msgBuf = nullptr;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&msgBuf,
		0, NULL);
	return (msgBuf == nullptr) ? wstring() : wstring(msgBuf);
}

OfflineHandler::OfflineHandler(const wstring& filePath, int tryWindow)
{
	// Load the offline file on startup
	_filePath = filePath.empty() ? _filePath : filePath;
	_tryWindow = tryWindow == 0 ? _tryWindow : tryWindow;
	const HRESULT res = LoadFromFile();
	if (res == S_OK)
	{
		PIDebug("Offline data loaded successfully!");
	}
	else if (res == ERROR_FILE_NOT_FOUND)
	{
		// File not found can be ignored as it expected when not using offline OTPs
	}
	else
	{
		PIDebug(L"Unable to load offline file: " + to_wstring(res) + L": " + getErrorText(res));
	}
}

OfflineHandler::~OfflineHandler()
{
	if (!_dataSets.empty())
	{
		const HRESULT res = SaveToFile();
		if (res != S_OK)
		{
			PIDebug(L"Unable to save offline file: " + to_wstring(res) + L": " + getErrorText(res));
		}
		else
		{
			PIDebug("Offline data saved successfully!");
		}
	}
}

HRESULT OfflineHandler::VerifyOfflineOTP(const std::wstring& otp, const std::string& username, std::string& serialUsed)
{
	HRESULT success = E_FAIL;
	for (auto& item : _dataSets)
	{
		if (Convert::ToUpperCase(item.username) == Convert::ToUpperCase(username))
		{
			PIDebug("Trying token " + item.serial);
			const int lowestKey = item.GetLowestKey();
			int matchingKey = lowestKey;

			for (int i = lowestKey; i < (lowestKey + _tryWindow); i++)
			{
				//DebugPrint("Key number: " + to_string(i));
				try
				{
					string storedValue = item.offlineOTPs.at(to_string(i));
					if (PBKDF2SHA512Verify(otp, storedValue))
					{
						matchingKey = i;
						success = S_OK;
						break;
					}
				}
				catch (const std::out_of_range& e)
				{
					UNREFERENCED_PARAMETER(e);
					// handle missing offline otps -> ignore (skip)
				}
			}

			if (success == S_OK)
			{
				// Also include if the matching is the first
				int count = 0;
				if (matchingKey >= lowestKey)
				{
					for (int i = lowestKey; i <= matchingKey; i++)
					{
						item.offlineOTPs.erase(to_string(i));
						count++;
					}
				}
				PIDebug("Offline authentication success with token " + item.serial + ", removing " + to_string(count) + " offline OTPs.");
				serialUsed = item.serial;
				// If success, stop trying other dataSets
				break;
			}
		}
	}

	return success;
}

HRESULT OfflineHandler::GetRefillToken(const std::string& username, const std::string& serial, std::string& refilltoken)
{
	for (const auto& item : _dataSets)
	{
		if (Convert::ToUpperCase(item.username) == Convert::ToUpperCase(username) && item.serial == serial)
		{
			if (item.refilltoken.empty()) return PI_OFFLINE_NO_OFFLINE_DATA;
			refilltoken = string(item.refilltoken);
			return S_OK;
		}
	}

	return PI_OFFLINE_NO_OFFLINE_DATA;
}

HRESULT OfflineHandler::AddOfflineData(const OfflineData& data)
{
	// Check if the user already has data first, then add
	bool done = false;
	for (auto& existing : _dataSets)
	{
		if (Convert::ToUpperCase(existing.username) == Convert::ToUpperCase(data.username) && existing.serial == data.serial)
		{
			PIDebug("Offline: Updating exsisting user data for " + data.username + " and token " + data.serial);
			existing.refilltoken = data.refilltoken;

			for (const auto& newOTP : data.offlineOTPs)
			{
				existing.offlineOTPs.try_emplace(newOTP.first, newOTP.second);
			}
			done = true;
		}
	}

	if (!done)
	{
		_dataSets.push_back(data);
		PIDebug("Offline: Adding new data for " + data.username + " and token " + data.serial);
	}

	return S_OK;
}

size_t OfflineHandler::GetOfflineOTPCount(const std::string& username, const std::string& serial)
{
	for (auto& item : _dataSets)
	{
		if (Convert::ToUpperCase(item.username) == Convert::ToUpperCase(username) && item.serial == serial)
		{
			return item.offlineOTPs.size();
		}
	}

	return 0;
}

std::vector<std::pair<std::string, size_t>> OfflineHandler::GetTokenInfo(const std::string& username)
{
	std::vector<std::pair<std::string, size_t>> ret;
	for (auto& item : _dataSets)
	{
		if (Convert::ToUpperCase(item.username) == Convert::ToUpperCase(username))
		{
			ret.push_back(make_pair(item.serial, item.offlineOTPs.size()));
		}
	}
	return ret;
}

std::vector<OfflineData> OfflineHandler::GetWebAuthnOfflineData(const std::string& username)
{
	std::vector<OfflineData> ret;
	for (auto& item : _dataSets)
	{
		if (Convert::ToUpperCase(item.username) == Convert::ToUpperCase(username) && item.isWebAuthn())
		{
			ret.push_back(item);
		}
	}
	return ret;
}

bool OfflineHandler::RemoveOfflineData(const std::string& username, const std::string& serial)
{
	bool found = false;
	for (auto& item : _dataSets)
	{
		if (Convert::ToUpperCase(item.username) == Convert::ToUpperCase(username) && item.serial == serial)
		{
			_dataSets.erase(std::remove(_dataSets.begin(), _dataSets.end(), item), _dataSets.end());
			found = true;
			break;
		}
	}

	if (!found)
	{
		PIDebug("Offline: No data to remove for " + username + " and token " + serial);
	}
	
	return found;
}

HRESULT OfflineHandler::SaveToFile()
{
	ofstream o;
	o.open(_filePath, ios_base::out); // Destroy contents | create new

	if (!o.is_open()) return GetLastError();
	JsonParser parser;
	string s = parser.OfflineDataToString(_dataSets);
	o << s;
	o.close();
	return S_OK;
}

HRESULT OfflineHandler::LoadFromFile()
{
	string fileContent;
	string line;
	ifstream ifs(_filePath);

	if (!ifs.good()) return GetLastError();

	if (ifs.is_open())
	{
		while (getline(ifs, line))
		{
			fileContent += line;
		}
		ifs.close();
	}

	if (fileContent.empty()) return PI_OFFLINE_FILE_EMPTY;

	JsonParser parser;
	auto vec = parser.ParseFileContentsForOfflineData(fileContent);

	for (auto& item : vec)
	{
		AddOfflineData(item);
	}

	return S_OK;
}

// Returns the outer right value of the passlib format and cuts it off the input string including the $
std::string OfflineHandler::GetNextValue(std::string& in)
{
	string tmp = in.substr(in.find_last_of('$') + 1);
	in = in.substr(0, in.find_last_of('$'));
	return tmp;
}

bool OfflineHandler::PBKDF2SHA512Verify(std::wstring password, std::string storedValue)
{
	bool isValid = false;
	// Format of stored values (passlib):
	// $algorithm$iteratons$salt$checksum
	string storedOTP = GetNextValue(storedValue);
	// $algorithm$iteratons$salt
	string salt = GetNextValue(storedValue);
	// $algorithm$iteratons
	int iterations = 10000;
	try
	{
		iterations = stoi(GetNextValue(storedValue));
	}
	catch (const invalid_argument& e)
	{
		PIDebug(e.what());
	}
	// $algorithm
	string algorithm = GetNextValue(storedValue);

	// Salt is in adapted abase64 encoding of passlib where [./+] is substituted
	Convert::Base64ToABase64(salt);

	int cbSalt = Base64DecodeGetRequiredLength((int)(salt.size() + 1));
	BYTE* pbSalt = (BYTE*)CoTaskMemAlloc(cbSalt);
	if (pbSalt == nullptr)
	{
		return false;
	}
	Base64Decode(salt.c_str(), (int)(salt.size() + 1), pbSalt, &cbSalt);

	// The password is encoded into UTF-8 from Unicode
	char* pszPassword = Convert::UnicodeToCodePage(65001, password.c_str());
	const int cbPassword = (int)strnlen_s(pszPassword, INT_MAX);
	BYTE* pbPassword = reinterpret_cast<unsigned char*>(pszPassword);

	// Get the size of the output from the stored value, which is also in abase64 encoding
	Convert::Base64ToABase64(storedOTP);

	int cbStoredOTP = Base64DecodeGetRequiredLength((int)(storedOTP.size() + 1));
	BYTE* pbStoredOTP = (BYTE*)CoTaskMemAlloc(cbStoredOTP);
	if (pbStoredOTP == nullptr)
	{
		return false;
	}
	Base64Decode(storedOTP.c_str(), (int)(storedOTP.size() + 1), pbStoredOTP, &cbStoredOTP);

	// Do PBKDF2
	const ULONGLONG ullIterations = iterations;
	ULONG cbDerivedKey = (ULONG)cbStoredOTP;
	PUCHAR pbDerivedKey = (unsigned char*)CoTaskMemAlloc(sizeof(unsigned char) * cbDerivedKey);
	if (pbDerivedKey == nullptr)
	{
		PIError("Could not allocate memory for derived key.");
		return false;
	}

	const ULONG dwFlags = 0; // RESERVED, MUST BE ZERO
	BCRYPT_ALG_HANDLE hPrf = BCRYPT_HMAC_SHA512_ALG_HANDLE;

	const NTSTATUS status =
		BCryptDeriveKeyPBKDF2(
			hPrf,
			pbPassword,
			cbPassword,
			pbSalt,
			cbSalt,
			ullIterations,
			pbDerivedKey,
			cbDerivedKey,
			dwFlags);

	CoTaskMemFree(pbSalt);

	if (status == 0) // STATUS_SUCCESS
	{
		// Compare the bytes
		if (cbDerivedKey == (ULONG)cbStoredOTP)
		{
			while (cbDerivedKey--)
			{
				if (pbDerivedKey[cbDerivedKey] != pbStoredOTP[cbDerivedKey])
				{
					goto Exit;
				}
			}
			isValid = true;
		}
	}
	else
	{
		PIDebug("PBKDF2 Error: " + to_string(status));
		isValid = false;
	}

Exit:
	SecureZeroMemory(pszPassword, sizeof(pszPassword));
	SecureZeroMemory(pbPassword, sizeof(pbPassword));
	CoTaskMemFree(pbDerivedKey);
	CoTaskMemFree(pbStoredOTP);

	return isValid;
}
