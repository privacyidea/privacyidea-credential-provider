/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2012 Dominik Pretzsch
**				2017 NetKnights GmbH
**
** Author		Dominik Pretzsch
**				Nils Behlen
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
** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#ifndef _HELPER_H
#define _HELPER_H
#pragma once

#include "common.h"
#include "data.h"
#include <stdio.h>
#include <tchar.h>
#include <chrono>
#include <ctime>
#include <string>
#include <codecvt>
#include <locale>

namespace Helper
{
	void RedrawGUI();

	std::wstring s2ws(const std::string& str);

	std::string ws2s(const std::wstring& wstr);

	void SeparateUserAndDomainName(
		__in wchar_t* domain_slash_username,
		__out wchar_t* username,
		__in int sizeUsername,
		__out_opt wchar_t* domain,
		__in_opt int sizeDomain
	);

	int GetFirstActiveIPAddress(
		__deref_out_opt char*& ip_addr
	);

	void WideCharToChar(
		__in PWSTR data,
		__in int buffSize,
		__out char* pc
	);

	void CharToWideChar(
		__in char* data,
		__in int buffSize,
		__out PWSTR pc
	);

	size_t iso8859_1_to_utf8(char* content, size_t max_size);

	// END
}

#endif

