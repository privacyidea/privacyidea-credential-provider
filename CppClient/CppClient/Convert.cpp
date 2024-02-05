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

#include "Convert.h"
#include "Logger.h"
#include <codecvt>
#include <sstream>
#include <algorithm>
#include <wincrypt.h>
#include <iomanip>
#include <iostream>

#pragma comment(lib, "crypt32.lib")


std::wstring Convert::ToWString(const std::string& s)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(s);
}

std::string Convert::ToString(const std::wstring& ws)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(ws);
}

std::string Convert::ToString(const bool b)
{
	return b ? std::string("true") : std::string("false");
}

std::wstring Convert::ToUpperCase(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::toupper(c)); });
	return s;
}

std::string Convert::ToUpperCase(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](char c) { return static_cast<char>(std::toupper(c)); });
	return s;
}

std::string Convert::LongToHexString(long in)
{
	std::stringstream ss;
	ss << std::hex << in;
	return "0x" + ss.str();
}

std::wstring Convert::JoinW(const std::vector<std::wstring>& elements, const wchar_t* separator)
{
	std::wstringstream os;
	for (std::vector<std::wstring>::const_iterator iter = elements.begin(); iter != elements.end(); ++iter)
	{
		os << *iter;
		if (iter + 1 != elements.end())
		{
			os << separator;
		}
	}
	return os.str();
}

std::vector<unsigned char> Convert::Base64Decode(const std::string& base64String)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	std::vector<unsigned char> decoded_data;
	size_t in_len = base64String.size();
	int i = 0;
	int j = 0;
	int in_ = 0;
	unsigned char char_array_4[4]{};
	unsigned char char_array_3[3]{};

	while (in_len-- && (base64String[in_] != '=') && (isalnum(base64String[in_]) 
		|| (base64String[in_] == '+') || (base64String[in_] == '/')))
	{
		char_array_4[i++] = base64String[in_];
		in_++;
		if (i == 4)
		{
			for (i = 0; i < 4; i++)
			{
				char_array_4[i] = base64_chars.find(char_array_4[i]);
			}
				
			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (i = 0; i < 3; i++)
			{
				decoded_data.push_back(char_array_3[i]);
			}
				
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 4; j++)
		{
			char_array_4[j] = 0;
		}

		for (j = 0; j < 4; j++)
		{
			char_array_4[j] = base64_chars.find(char_array_4[j]);
		}

		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

		for (j = 0; j < i - 1; j++)
		{
			decoded_data.push_back(char_array_3[j]);
		}
	}

	return decoded_data;
}

std::vector<unsigned char> Convert::Base64URLDecode(const std::string& base64String)
{
	std::string base64 = base64String;
	Convert::Base64URLToBase64(base64);
	return Base64Decode(base64);
}

std::string Convert::Base64Encode(const unsigned char* data, const size_t size, bool padded)
{
	static const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	size_t count = size;
	std::string encoded_string;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3]{};
	unsigned char char_array_4[4]{};

	while (count--)
	{
		char_array_3[i++] = *(data++);
		if (i == 3)
		{
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; i < 4; i++)
			{
				encoded_string += base64_chars[char_array_4[i]];
			}
				
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
		{
			char_array_3[j] = '\0';
		}

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; j < i + 1; j++)
		{
			encoded_string += base64_chars[char_array_4[j]];
		}
			
		if (padded)
		{
			while (i++ < 3)
			{
				encoded_string += '=';
			}
		}
	}

	return encoded_string;
}

std::string Convert::Base64Encode(const std::vector<unsigned char>& data, bool padded)
{
	return Base64Encode(data.data(), data.size(), padded);
}

std::string Convert::Base64URLEncode(const unsigned char* data, const size_t size, bool padded)
{
	std::string base64 = Base64Encode(data, size, padded);
	Convert::Base64ToBase64URL(base64);
	return base64;
}

std::string Convert::Base64URLEncode(const std::vector<unsigned char>& data, bool padded)
{
	return Base64URLEncode(data.data(), data.size(), padded);
}

std::string Convert::PByteToBase64(const PBYTE data, const DWORD dataSize)
{
	DWORD base64Len = 0;
	if (!CryptBinaryToStringA(data, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Len))
	{
		PIError("CryptBinaryToStringA failed to determine data size");
		return "";
	}

	std::string base64String;
	base64String.resize(base64Len);

	if (!CryptBinaryToStringA(data, dataSize, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64String[0], &base64Len))
	{
		PIError("CryptBinaryToStringA failed to convert data to base64 string");
		return "";
	}

	return base64String;
}

std::string Convert::PByteToBase64URL(const PBYTE data, const DWORD dataSize)
{
	auto res = Convert::PByteToBase64(data, dataSize);
	Convert::Base64ToBase64URL(res);
	auto ret = Convert::ReplaceAll(res, "=", "");
	return ret;
}

char* Convert::UnicodeToCodePage(int codePage, const wchar_t* src)
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

void Convert::Base64ToBase64URL(std::string& base64)
{
	std::replace(base64.begin(), base64.end(), '+', '-');
	std::replace(base64.begin(), base64.end(), '/', '_');
}

void Convert::Base64URLToBase64(std::string& base64URL)
{
	std::replace(base64URL.begin(), base64URL.end(), '-', '+');
	std::replace(base64URL.begin(), base64URL.end(), '_', '/');
}

void Convert::Base64ToABase64(std::string& base64)
{
	std::replace(base64.begin(), base64.end(), '.', '+');
}

std::string Convert::BytesToHex(std::vector<unsigned char> bytes)
{
	return BytesToHex(bytes.data(), bytes.size());
}

std::string Convert::BytesToHex(const unsigned char* data, const size_t dataSize)
{
	std::stringstream ss;
	for (unsigned char c : std::vector<unsigned char>(data, data + dataSize))
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
	}
	return ss.str();
}

std::vector<unsigned char> Convert::HexToBytes(const std::string& hexString)
{
	std::vector<unsigned char> binaryData;
	for (size_t i = 0; i < hexString.length(); i += 2)
	{
		std::string byteString = hexString.substr(i, 2);
		unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
		binaryData.push_back(byte);
	}
	return binaryData;
}

std::string Convert::ReplaceAll(const std::string& input, const std::string& target, const std::string& replacement)
{
	// Replace all occurences of target in input with replacement
	std::string result = input;
	size_t pos = 0;
	while ((pos = result.find(target, pos)) != std::string::npos)
	{
		result.replace(pos, target.length(), replacement);
		pos += replacement.length();
	}
	return result;
}
