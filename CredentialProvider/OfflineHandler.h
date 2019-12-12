#pragma once
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

#include "nlohmann/json.hpp"
#include "OfflineData.h"
#include <string>
#include <map>
#include <Windows.h>
#include <vector>

#define OFFLINE_FILE_DOES_NOT_EXIST		((HRESULT)0x88809010) // Not an error
#define OFFLINE_FILE_EMPTY				((HRESULT)0x88809011)
#define OFFLINE_JSON_FORMAT_ERROR		((HRESULT)0x88809012)
#define OFFLINE_JSON_PARSE_ERROR		((HRESULT)0x88809014)

#define OFFLINE_DATA_NO_OTPS_LEFT		((HRESULT)0x88809020)
#define OFFLINE_DATA_USER_NOT_FOUND		((HRESULT)0x88809021)
#define OFFLINE_NO_OFFLINE_DATA			((HRESULT)0x88809022) 

class OfflineHandler
{
public:
	OfflineHandler(std::string filePath, int tryWindow);

	~OfflineHandler();

	HRESULT verifyOfflineOTP(std::wstring otp, std::string username);

	int getOfflineValuesLeft(std::string username);

	HRESULT getRefillTokenAndSerial(std::string username, __out std::map<std::string, std::string>& map);

	HRESULT parseForOfflineData(std::string in);

	HRESULT parseRefillResponse(std::string in, std::string username);

	HRESULT getLastErrorCode();

	HRESULT isDataVailable(std::string username);

private:
	std::vector<OfflineData> dataSets = std::vector<OfflineData>();

	std::string _filePath = "";

	int _tryWindow = 10;

	bool pbkdf2_sha512_verify(std::wstring password, std::string storedValue);

	void base64toabase64(std::string& in);

	std::string getNextValue(std::string& in);

	char* UnicodeToCodePage(int codePage, const wchar_t* src);

	wchar_t* CodePageToUnicode(int codePage, const char* src);

	HRESULT saveToFile();

	HRESULT loadFromFile();

	HRESULT _lastError;
};

