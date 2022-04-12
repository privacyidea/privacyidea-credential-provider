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
#include <iostream>
#include <fstream>
#include <atlenc.h>
#include <algorithm>

#pragma comment (lib, "bcrypt.lib")

using namespace std;

std::wstring getErrorText(DWORD err)
{
	LPWSTR msgBuf;
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
		DebugPrint("Offline data loaded successfully!");
	}
	else if (res == ERROR_FILE_NOT_FOUND)
	{
		// File not found can be ignored as it expected when not using offline OTPs
	}
	else
	{
		DebugPrint(L"Unable to load offline file: " + to_wstring(res) + L": " + getErrorText(res));
	}
}

OfflineHandler::~OfflineHandler()
{
	if (!dataSets.empty())
	{
		const HRESULT res = SaveToFile();
		if (res != S_OK)
		{
			DebugPrint(L"Unable to save offline file: " + to_wstring(res) + L": " + getErrorText(res));
		}
		else
		{
			DebugPrint("Offline data saved successfully!");
		}
	}
}

HRESULT OfflineHandler::VerifyOfflineOTP(const std::wstring& otp, const string& username)
{
	HRESULT success = E_FAIL;

	for (auto& item : dataSets)
	{
		if (item.username == username)
		{
			DebugPrint("Trying token " + item.serial);
			const int lowestKey = item.GetLowestKey();
			int matchingKey = lowestKey;

			for (int i = lowestKey; i < (lowestKey + _tryWindow); i++)
			{
				try
				{
					string storedValue = item.offlineOTPs.at(to_string(i));
					if (Pbkdf2_sha512_verify(otp, storedValue))
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
				if (matchingKey >= lowestKey)
				{
					for (int i = lowestKey; i <= matchingKey; i++)
					{
						item.offlineOTPs.erase(to_string(i));
					}
				}
				DebugPrint("Offline authentication success with token " + item.serial);
				// If success, stop trying other dataSets
				break;
			}
		}
	}

	return success;
}

HRESULT OfflineHandler::GetRefillTokenAndSerial(const std::string& username, std::string& refilltoken, std::string& serial)
{
	for (const auto& item : dataSets)
	{
		if (item.username == username)
		{
			if (item.serial.empty() || item.refilltoken.empty()) return PI_OFFLINE_NO_OFFLINE_DATA;
			refilltoken = string(item.refilltoken);;
			serial = string(item.serial);;
			return S_OK;
		}
	}

	return PI_OFFLINE_NO_OFFLINE_DATA;
}

HRESULT OfflineHandler::DataVailable(const std::string& username)
{
	for (auto& item : dataSets)
	{
		if (item.username == username)
		{
			return (item.offlineOTPs.empty() ? PI_OFFLINE_DATA_NO_OTPS_LEFT : S_OK);
		}
	}

	return PI_OFFLINE_NO_OFFLINE_DATA;
}

HRESULT OfflineHandler::AddOfflineData(const OfflineData& data)
{
	// Check if the user already has data first, then add
	bool done = false;
	for (auto& existing : dataSets)
	{
		if (existing.username == data.username && existing.serial == data.serial)
		{
			DebugPrint("Offline: Updating exsisting user data for " + data.username + " and token " + data.serial);
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
		dataSets.push_back(data);
		DebugPrint("Offline: Adding new data for " + data.username + " and token " + data.serial);
	}

	return S_OK;
}

size_t OfflineHandler::GetOfflineOTPCount(const std::string& username)
{
	for (auto& item : dataSets)
	{
		if (item.username == username)
		{
			return item.offlineOTPs.size();
		}
	}

	return 0;
}

std::vector<std::pair<std::string, size_t>> OfflineHandler::GetTokenInfo(const std::string& username)
{
	std::vector<std::pair<std::string, size_t>> ret;
	for (auto& item : dataSets)
	{
		if (item.username == username)
		{
			ret.push_back(make_pair(item.serial, item.offlineOTPs.size()));
		}
	}
	return ret;
}

HRESULT OfflineHandler::SaveToFile()
{
	ofstream o;
	o.open(_filePath, ios_base::out); // Destroy contents | create new

	if (!o.is_open()) return GetLastError();
	JsonParser parser;
	string s = parser.OfflineDataToString(dataSets);
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

char* OfflineHandler::UnicodeToCodePage(int codePage, const wchar_t* src)
{
	if (!src) return 0;
	int srcLen = (int)wcslen(src);
	if (!srcLen)
	{
		char* x = new char[1];
		x[0] = '\0';
		return x;
	}

	int requiredSize = WideCharToMultiByte(codePage,
		0,
		src, srcLen, 0, 0, 0, 0);

	if (!requiredSize)
	{
		return 0;
	}

	char* x = new char[(LONGLONG)requiredSize + 1];
	x[requiredSize] = 0;

	int retval = WideCharToMultiByte(codePage,
		0,
		src, srcLen, x, requiredSize, 0, 0);
	if (!retval)
	{
		delete[] x;
		return nullptr;
	}

	return x;
}

bool OfflineHandler::Pbkdf2_sha512_verify(std::wstring password, std::string storedValue)
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
		DebugPrint(e.what());
	}
	// $algorithm
	string algorithm = GetNextValue(storedValue);

	// Salt is in adapted abase64 encoding of passlib where [./+] is substituted
	Base64toabase64(salt);

	int bufLen = Base64DecodeGetRequiredLength((int)(salt.size() + 1));
	BYTE* bufSalt = (BYTE*)CoTaskMemAlloc(bufLen);
	if (bufSalt == nullptr)
	{
		return false;
	}
	Base64Decode(salt.c_str(), (int)(salt.size() + 1), bufSalt, &bufLen);

	// The password is encoded into UTF-8 from Unicode
	char* prepPassword = UnicodeToCodePage(65001, password.c_str());
	const int prepPasswordSize = (int)strnlen_s(prepPassword, INT_MAX);

	BYTE* prepPasswordBytes = reinterpret_cast<unsigned char*>(prepPassword);

	// Get the size of the output from the stored value, which is also in abase64 encoding
	Base64toabase64(storedOTP);

	int bufLenStored = Base64DecodeGetRequiredLength((int)(storedOTP.size() + 1));
	BYTE* bufStored = (BYTE*)CoTaskMemAlloc(bufLenStored);
	if (bufStored == nullptr)
	{
		return false;
	}
	Base64Decode(storedOTP.c_str(), (int)(storedOTP.size() + 1), bufStored, &bufLenStored);

	// Do PBKDF2
	const ULONGLONG cIterations = iterations;
	ULONG cbDerivedKey = (ULONG)bufLenStored;
	PUCHAR pbDerivedKey = (unsigned char*)CoTaskMemAlloc(sizeof(unsigned char) * cbDerivedKey);
	if (pbDerivedKey == nullptr)
	{
		DebugPrint("Could not allocate memory for derived key.");
		return false;
	}

	const ULONG dwFlags = 0; // RESERVED, MUST BE ZERO
	BCRYPT_ALG_HANDLE hPrf = BCRYPT_HMAC_SHA512_ALG_HANDLE;

	const NTSTATUS status = BCryptDeriveKeyPBKDF2(hPrf, prepPasswordBytes, prepPasswordSize, bufSalt, bufLen,
		cIterations, pbDerivedKey, cbDerivedKey, dwFlags);

	CoTaskMemFree(bufSalt);

	if (status == 0) // STATUS_SUCCESS
	{
		// Compare the bytes
		if (cbDerivedKey == (ULONG)bufLenStored)
		{
			while (cbDerivedKey--)
			{
				if (pbDerivedKey[cbDerivedKey] != bufStored[cbDerivedKey])
				{
					goto Exit;
				}
			}
			isValid = true;
		}
	}
	else
	{
		DebugPrint("PBKDF2 Error: " + to_string(status));
		isValid = false;
	}

Exit:
	SecureZeroMemory(prepPassword, sizeof(prepPassword));
	SecureZeroMemory(prepPasswordBytes, sizeof(prepPasswordBytes));
	CoTaskMemFree(pbDerivedKey);
	CoTaskMemFree(bufStored);

	return isValid;
}

// Replaces '.' with '+' in the input string.
void OfflineHandler::Base64toabase64(std::string& in)
{
	std::replace(in.begin(), in.end(), '.', '+');
}
