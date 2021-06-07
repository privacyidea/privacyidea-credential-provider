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

#include "OfflineData.h"
#include <map>
#include <Windows.h>
#include <vector>

class OfflineHandler
{
public:
	OfflineHandler(const std::wstring& filePath, int tryWindow = 10);

	~OfflineHandler();

	HRESULT VerifyOfflineOTP(const std::wstring& otp, const std::string& username);

	HRESULT GetRefillTokenAndSerial(const std::string& username, std::string& refilltoken, std::string& serial);

	HRESULT ParseForOfflineData(const std::string& in);

	HRESULT ParseRefillResponse(const std::string& in, const std::string& username);

	HRESULT DataVailable(const std::string& username);

private:
	std::vector<OfflineData> dataSets = std::vector<OfflineData>();

	std::wstring _filePath = L"C:\\offlineFile.json";

	int _tryWindow = 10;

	bool Pbkdf2_sha512_verify(std::wstring password, std::string storedValue);

	void Base64toabase64(std::string& in);

	std::string GetNextValue(std::string& in);

	char* UnicodeToCodePage(int codePage, const wchar_t* src);

	HRESULT SaveToFile();

	HRESULT LoadFromFile();
};

