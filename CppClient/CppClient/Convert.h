/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2024 NetKnights GmbH
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

#pragma once
#include <string>
#include <vector>
#include <Windows.h>

class Convert
{
public:
	static std::wstring ToWString(const std::string& s);
	static std::string ToString(const std::wstring& ws);
	static std::string ToString(const bool b);
	static std::wstring ToUpperCase(std::wstring s);
	static std::string ToUpperCase(std::string s);
	static std::string LongToHexString(long in);
	static std::wstring JoinW(const std::vector<std::wstring>& elements, const wchar_t* separator);
	
	static std::vector<unsigned char> Base64Decode(const std::string& base64String);
	static std::vector<unsigned char> Base64URLDecode(const std::string& base64String);
	static std::string Base64Encode(const unsigned char* data, const size_t size, bool padded = false);
	static std::string Base64Encode(const std::vector<unsigned char>& data, bool padded = false);
	static std::string Base64URLEncode(const unsigned char* data, const size_t size, bool padded = false);
	static std::string Base64URLEncode(const std::vector<unsigned char>& data, bool padded = false);

	static std::string PByteToBase64(const PBYTE data, const DWORD dataSize);
	static std::string PByteToBase64URL(const PBYTE data, const DWORD dataSize);
	
	static char* UnicodeToCodePage(int codePage, const wchar_t* src);
	// replace '+' with '-' and '/' with '_'
	static void Base64ToBase64URL(std::string& base64);
	// replace '-' with '+' and '_' with '/'
	static void Base64URLToBase64(std::string& base64URL);

	// Replaces '.' with '+'.
	static void Base64ToABase64(std::string& base64);

	static std::string BytesToHex(const unsigned char* data, const size_t dataSize);
	static std::string BytesToHex(std::vector<unsigned char> bytes);

	static std::vector<unsigned char> HexToBytes(const std::string& hexString);

	static std::string ReplaceAll(const std::string& input, const std::string& target, const std::string& replacement);
};
