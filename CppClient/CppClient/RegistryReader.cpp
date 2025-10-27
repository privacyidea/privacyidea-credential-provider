/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
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
#include "RegistryReader.h"
#include "Convert.h"
#include <Windows.h>
#include <tchar.h>
#include "Logger.h"

using namespace std;

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 1024

RegistryReader::RegistryReader(const std::wstring& pathToKey) noexcept
{
	path = pathToKey;
}

bool RegistryReader::GetAll(const std::wstring& pathToKey, std::map<std::wstring, std::wstring>& map) noexcept
{
	// Open handle to realm-mapping key
	HKEY hKey = nullptr;
	auto dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, pathToKey.c_str(), 0, KEY_READ, &hKey);
	if (dwRet != ERROR_SUCCESS)
	{
		PIError("Failed to open registry key " + Convert::ToString(pathToKey) + ", error: " + Convert::LongToHexString(dwRet));
		return false;
	}

	WCHAR    achClass[MAX_PATH] = TEXT(""); // buffer for class name 
	DWORD    cchClassName = MAX_PATH;		// size of class string 
	DWORD    cSubKeys = 0;					// number of subkeys 
	DWORD    cbMaxSubKey;					// longest subkey size 
	DWORD    cchMaxClass;					// longest class string 
	DWORD    cValues;						// number of values for key 
	DWORD    cchMaxValue;					// longest value name 
	DWORD    cbMaxValueData;				// longest value data 
	DWORD    cbSecurityDescriptor;			// size of security descriptor 
	FILETIME ftLastWriteTime;				// last write time 

	DWORD i, retCode;

	WCHAR achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	if (cValues)
	{
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValueW(hKey, i,
				achValue,
				&cchValue,
				NULL,
				NULL,
				NULL,
				NULL);
			if (retCode == ERROR_SUCCESS)
			{
				wstring value = Convert::ToUpperCase(achValue);
				// Get the data for the value
				const DWORD SIZE = 1024;
				TCHAR szData[SIZE] = _T("");
				DWORD dwValue = SIZE;
				DWORD dwType = 0;
				DWORD dwRet = 0;

				dwRet = RegQueryValueEx(
					hKey,
					value.c_str(),
					NULL,
					&dwType,
					(LPBYTE)&szData,
					&dwValue);
				if (dwRet == ERROR_SUCCESS)
				{
					if (dwType == REG_SZ)
					{
						wstring data(szData);
						map.try_emplace(value, data);
					}
				}
			}
			else
			{
				PIError("Failed to read registry value at index " + to_string(i) + " in key " + Convert::ToString(pathToKey) +
					", error: " + Convert::LongToHexString(retCode));
			}
		}
	}

	RegCloseKey(hKey);
	return true;
}

std::wstring RegistryReader::GetWString(std::wstring name) noexcept
{
	DWORD dwRet = NULL;
	HKEY hKey = nullptr;
	dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), NULL, KEY_QUERY_VALUE, &hKey);
	if (dwRet != ERROR_SUCCESS)
	{
		PIError("Failed to open registry key " + Convert::ToString(path) + ", error: " + Convert::LongToHexString(dwRet));
		return L"";
	}

	const DWORD SIZE = 1024;
	TCHAR szValue[SIZE] = _T("");
	DWORD dwValue = SIZE;
	DWORD dwType = 0;
	dwRet = RegQueryValueEx(hKey, name.c_str(), NULL, &dwType, (LPBYTE)&szValue, &dwValue);
	if (dwRet != ERROR_SUCCESS)
	{
		PIError("Failed to read registry value " + Convert::ToString(name) + ", error: " + Convert::LongToHexString(dwRet));
		return L"";
	}

	if (dwType != REG_SZ)
	{
		PIError("Type of registry value " + Convert::ToString(name) + " is not REG_SZ, but " + Convert::LongToHexString(dwType));
		return L"";
	}
	RegCloseKey(hKey);
	hKey = NULL;
	return wstring(szValue);
}

bool RegistryReader::GetBool(std::wstring name) noexcept
{
	// Non existing keys evaluate to false.
	return GetWString(name) == L"1";
}

int RegistryReader::GetInt(std::wstring name) noexcept
{
	return _wtoi(GetWString(name).c_str()); // Invalid parameter returns 0
}

std::vector<std::wstring> RegistryReader::GetMultiSZ(const std::wstring& valueName) noexcept
{
	HKEY hKey;
	LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &hKey);
	if (result != ERROR_SUCCESS)
	{
		PIError("Failed to open registry key " + Convert::ToString(path) + ", error: " + Convert::LongToHexString(result));
		return std::vector<std::wstring>();
	}

	DWORD dwType = REG_MULTI_SZ, dwSize = 0;
	result = RegQueryValueEx(hKey, valueName.c_str(), 0, &dwType, 0, &dwSize);
	if (result != ERROR_SUCCESS)
	{
		PIError("Failed to query size of registry value " + Convert::ToString(valueName) + ", error: " + Convert::LongToHexString(result));
		return std::vector<std::wstring>();
	}

	std::vector<wchar_t> buffer(dwSize);
	result = RegQueryValueEx(hKey, valueName.c_str(), 0, &dwType, (LPBYTE)buffer.data(), &dwSize);
	if (result != ERROR_SUCCESS)
	{
		PIError("Failed to read registry value " + Convert::ToString(valueName) + ", error: " + Convert::LongToHexString(result));
		return std::vector<std::wstring>();
	}

	std::vector<std::wstring> strings;
	for (wchar_t* p = buffer.data(); *p != '\0'; p += lstrlen(p) + 1)
	{
		strings.push_back(p);
	}

	return strings;
}
