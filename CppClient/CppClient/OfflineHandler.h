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

// 888090-2X OFFLINE
#define PI_OFFLINE_DATA_NO_OTPS_LEFT				((HRESULT)0x88809020)
#define PI_OFFLINE_NO_OFFLINE_DATA					((HRESULT)0x88809022) 
#define PI_OFFLINE_FILE_DOES_NOT_EXIST				((HRESULT)0x88809023)
#define PI_OFFLINE_FILE_EMPTY						((HRESULT)0x88809024)
#define PI_OFFLINE_WRONG_OTP						((HRESULT)0x88809025)

class OfflineHandler
{
public:
	OfflineHandler(const std::wstring& filePath, int tryWindow = 10);

	~OfflineHandler();

	/*!
		Check if the given OTP matches with one of the offline OTPs in the configured window.
		If the given OTP is not the first in the list, the values between the start of the list and the matching position are removed.

		@param[in] OTP
		@param[in] Username
		@param[out] serialUsed
		@returns S_OK or E_FAIL
	*/
	HRESULT VerifyOfflineOTP(const std::wstring& otp, const std::string& username, std::string& serialUsed);

	HRESULT GetRefillToken(const std::string& username, const std::string& serial, std::string& refilltoken);

	HRESULT AddOfflineData(const OfflineData& data);

	/// <summary>
	/// Get the number of remaining offline OTPs for the user. 
	/// </summary>
	/// <param name="username"></param>
	/// <returns>The number of remaining offline OTP values or 0 if no data is found</returns>
	size_t GetOfflineOTPCount(const std::string& username, const std::string& serial);

	std::vector<std::pair<std::string, size_t>> GetTokenInfo(const std::string& username);

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

