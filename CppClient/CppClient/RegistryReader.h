/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
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
#include <map>
#include <vector>

constexpr auto CONFIG_REGISTRY_PATH = L"SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\";
constexpr auto REALM_MAPPING_REGISTRY_PATH = L"SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\realm-mapping";
constexpr auto LAST_USER_REGISTRY_PATH = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI";

class RegistryReader
{
public:

	RegistryReader(const std::wstring& pathToKey) noexcept;

	std::wstring path;

	// puts all keys and values from the current path into a map, the keys will be converted to uppercase
	bool GetAll(const std::wstring& pathToKey, std::map<std::wstring, std::wstring>& map) noexcept;

	std::wstring GetWString(std::wstring name) noexcept;

	bool GetBool(std::wstring name) noexcept;

	int GetInt(std::wstring name) noexcept;

	std::vector<std::wstring> GetMultiSZ(const std::wstring& valueName) noexcept;
};
