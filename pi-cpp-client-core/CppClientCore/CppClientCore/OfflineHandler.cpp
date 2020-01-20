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
#include "Endpoint.h"
#include <iostream>
#include <fstream>
#include <atlenc.h>

#pragma comment (lib, "bcrypt.lib")

using namespace std;
using json = nlohmann::json;

OfflineHandler::OfflineHandler(const string& filePath, int tryWindow)
{
	// Load the offline file on startup
	_filePath = filePath;
	_tryWindow = tryWindow;
	if (loadFromFile() != S_OK)
	{
	}
}

OfflineHandler::~OfflineHandler()
{
	const HRESULT res = saveToFile();
	if (res != S_OK)
	{
		DebugPrint("Unable to save offline file: " + to_string(res));
	}
}

HRESULT OfflineHandler::verifyOfflineOTP(const wstring& otp, const string& username)
{
	HRESULT success = E_FAIL;

	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			const int lowestKey = item.getLowestKey();
			int matchingKey = lowestKey;

			for (int i = lowestKey; i < (lowestKey + _tryWindow); i++)
			{
				try
				{
					string storedValue = item.offlineOTPs.at(to_string(i));
					if (pbkdf2_sha512_verify(otp, storedValue))
					{
						matchingKey = i;
						success = S_OK;
						break;
					}
				}
				catch (const std::out_of_range & e)
				{
					UNREFERENCED_PARAMETER(e);
					// TODO nothing, just skip?
				}
			}

			if (success == S_OK)
			{
				if (matchingKey >= lowestKey) // Also include if the matching is the first
				{
					cout << "difference: " << (matchingKey - lowestKey) << endl;
					for (int i = lowestKey; i <= matchingKey; i++)
					{
						item.offlineOTPs.erase(to_string(i));
					}
				}
			}
		}
	}

	return success;
}

int OfflineHandler::getOfflineValuesLeft(const std::string& username)
{
	if (dataSets.empty()) return -1;

	for (const auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			return item.offlineOTPs.size();
		}
	}

	return -1;
}

HRESULT OfflineHandler::getRefillTokenAndSerial(const std::string& username, std::map<std::string, std::string>& map)
{
	if (dataSets.empty()) return PI_NO_OFFLINE_DATA;

	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			string serial = item.serial;
			string refilltoken = item.refilltoken;
			if (serial.empty() || refilltoken.empty()) return PI_NO_OFFLINE_DATA;
			map.try_emplace("serial", serial);
			map.try_emplace("refilltoken", refilltoken);
			return S_OK;

		}
	}

	return OFFLINE_DATA_USER_NOT_FOUND;
}

// Check an authentication reponse from privacyIDEA if it contains the inital data for offline
HRESULT OfflineHandler::parseForOfflineData(const std::string& in)
{
	if (in.empty()) return E_FAIL;

	json j;
	try
	{
		j = json::parse(in);
	}
	catch (const json::parse_error & e)
	{
		DebugPrint(e.what());
		return OFFLINE_JSON_PARSE_ERROR;
	}

	auto jAuth_items = j["auth_items"];
	if (jAuth_items == NULL) return PI_NO_OFFLINE_DATA;

	// Get the serial to add to the data
	auto jSerial = j["detail"]["serial"];
	if (!jSerial.is_string()) return OFFLINE_JSON_FORMAT_ERROR;
	string serial = jSerial.get<std::string>();

	auto jOffline = jAuth_items["offline"];

	if (!jOffline.is_array()) return OFFLINE_JSON_FORMAT_ERROR;
	if (jOffline.size() < 1) return PI_NO_OFFLINE_DATA;

	for (const auto& item : jOffline)
	{
		OfflineData d(item.dump());
		d.serial = serial;
		dataSets.push_back(d);
	}
	return S_OK;
}

HRESULT OfflineHandler::parseRefillResponse(const std::string& in, const std::string& username)
{
	json jIn;
	try
	{
		jIn = json::parse(in);
	}
	catch (const json::parse_error & e)
	{
		DebugPrint(e.what());
		return OFFLINE_JSON_PARSE_ERROR;
	}
	// Set the new refill token
	json offline;
	try
	{
		offline = jIn["auth_items"]["offline"].at(0);
	}
	catch (const std::exception & e)
	{
		DebugPrint(e.what());
		return OFFLINE_JSON_FORMAT_ERROR;
	}

	if (offline == nullptr) return OFFLINE_JSON_FORMAT_ERROR;

	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			// TODO if there is no refill token then what? 
			// still adding the values we got
			if (offline["refilltoken"].is_string())
			{
				item.refilltoken = offline["refilltoken"].get<std::string>();
			}
			else
			{
				item.refilltoken = "";
			}

			auto jResponse = offline["response"];
			for (const auto& jItem : jResponse.items())
			{
				string key = jItem.key();
				string value = jItem.value();
				item.offlineOTPs.try_emplace(key, value);
			}
			return S_OK;
		}
	}

	return E_FAIL;
}

HRESULT OfflineHandler::isDataVailable(const std::string& username)
{
	// Check is usable data available for the given username
	for (auto& item : dataSets)
	{
		if (item.user == username || item.username == username)
		{
			return (item.offlineOTPs.empty() ? OFFLINE_DATA_NO_OTPS_LEFT : S_OK);
		}
	}

	return OFFLINE_DATA_USER_NOT_FOUND;
}

HRESULT OfflineHandler::saveToFile()
{
	ofstream o;
	o.open(_filePath, ios_base::out); // Destroy contents | create new

	if (!o.is_open()) return GetLastError();

	json::array_t jArr;

	for (auto& item : dataSets)
	{
		jArr.push_back(item.toJSON());
	}

	json j;
	j["offline"] = jArr;

	o << j.dump(4);
	o.close();
	return S_OK;
}

HRESULT OfflineHandler::loadFromFile()
{
	// Check for the file, load if exists
	string fileContent = "";
	string line;
	ifstream ifs(_filePath);

	if (!ifs.good()) return OFFLINE_FILE_DOES_NOT_EXIST;

	if (ifs.is_open())
	{
		while (getline(ifs, line))
		{
			fileContent += line;
		}
		ifs.close();
	}

	if (fileContent.empty()) return OFFLINE_FILE_EMPTY;

	try
	{
		auto j = json::parse(fileContent);

		auto jOffline = j["offline"];

		if (jOffline.is_array())
		{
			for (auto const& item : jOffline)
			{
				OfflineData d(item.dump());
				dataSets.push_back(d);
			}
		}
	}
	catch (const json::parse_error & e)
	{
		DebugPrint(e.what());
		return OFFLINE_JSON_PARSE_ERROR;
	}

	return S_OK;
}

// 65001 is utf-8.
wchar_t* OfflineHandler::CodePageToUnicode(int codePage, const char* src)
{
	if (!src) return 0;
	const int srcLen = strlen(src);
	if (!srcLen)
	{
		wchar_t* w = new wchar_t[1];
		w[0] = 0;
		return w;
	}

	int requiredSize = MultiByteToWideChar(codePage,
		0,
		src, srcLen, 0, 0);

	if (!requiredSize)
	{
		return 0;
	}

	wchar_t* w = new wchar_t[requiredSize + 1];
	w[requiredSize] = 0;

	const int retval = MultiByteToWideChar(codePage,
		0,
		src, srcLen, w, requiredSize);
	if (!retval)
	{
		delete[] w;
		return nullptr;
	}

	return w;
}

// Returns the outer right value of the passlib format and cuts it off the input string including the $
std::string OfflineHandler::getNextValue(std::string& in)
{
	string tmp = in.substr(in.find_last_of('$') + 1);
	in = in.substr(0, in.find_last_of('$'));
	return tmp;
}

char* OfflineHandler::UnicodeToCodePage(int codePage, const wchar_t* src)
{
	if (!src) return 0;
	int srcLen = wcslen(src);
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

	char* x = new char[requiredSize + 1];
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

bool OfflineHandler::pbkdf2_sha512_verify(std::wstring password, std::string storedValue)
{
	bool isValid = false;
	// Format of stored values (passlib):
	// $algorithm$iteratons$salt$checksum
	string storedOTP = getNextValue(storedValue);
	// $algorithm$iteratons$salt
	string salt = getNextValue(storedValue);
	// $algorithm$iteratons
	int iterations = 1000; // TODO default useful??
	try
	{
		iterations = stoi(getNextValue(storedValue));
	}
	catch (const invalid_argument & e)
	{
		DebugPrint(e.what());
	}
	// $algorithm
	string algorithm = getNextValue(storedValue);

	// Salt is in adapted abase64 encoding of passlib where [./+] is substituted
	base64toabase64(salt);

	int bufLen = Base64DecodeGetRequiredLength(salt.size() + 1);
	BYTE* bufSalt = (BYTE*)CoTaskMemAlloc(bufLen);
	if (bufSalt == nullptr) return false;
	Base64Decode(salt.c_str(), (salt.size() + 1), bufSalt, &bufLen);

	// The password is encoded into UTF-8 from Unicode
	char* prepPassword = UnicodeToCodePage(65001, password.c_str());
	const int prepPasswordSize = strlen(prepPassword);

	BYTE* prepPasswordBytes = reinterpret_cast<unsigned char*>(prepPassword);

	// Get the size of the output from the stored value, which is also in abase64 encoding
	base64toabase64(storedOTP);

	int bufLenStored = Base64DecodeGetRequiredLength(storedOTP.size() + 1);
	BYTE* bufStored = (BYTE*)CoTaskMemAlloc(bufLenStored);
	if (bufStored == nullptr) return false;
	Base64Decode(storedOTP.c_str(), storedOTP.size() + 1, bufStored, &bufLenStored);

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
		if (cbDerivedKey == bufLenStored)
		{
			while (cbDerivedKey--)
			{
				if (pbDerivedKey[cbDerivedKey] != bufStored[cbDerivedKey])
				{
					CoTaskMemFree(pbDerivedKey);
					CoTaskMemFree(bufStored);
					return false;
				}
			}
			isValid = true;
		}
	}
	else
	{
		printf("Error: %x", status);
		isValid = false;
	}

	CoTaskMemFree(pbDerivedKey);
	CoTaskMemFree(bufStored);

	return isValid;
}

// Replaces '.' with '+' in the input string.
void OfflineHandler::base64toabase64(std::string& in)
{
	std::replace(in.begin(), in.end(), '.', '+');
}