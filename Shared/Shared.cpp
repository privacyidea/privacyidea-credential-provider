/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2020 NetKnights GmbH
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

#include "Shared.h"
#include "Logger.h"
#include "RegistryReader.h"
#include "Convert.h"
#include <tchar.h>

namespace Shared
{
	bool IsRequiredForScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, int caller)
	{
		PIDebug(__FUNCTION__);
		if (caller != FILTER && caller != PROVIDER)
		{
			PIDebug("Invalid argument for caller: " + std::to_string(caller));
			return false;
		}

		RegistryReader rr(L"SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\");
		std::wstring entry;
		const bool isRemote = Shared::IsCurrentSessionRemote();
		switch (cpus)
		{
			case CPUS_LOGON:
			{
				entry = rr.GetWString(L"cpus_logon");
				break;
			}
			case CPUS_UNLOCK_WORKSTATION:
			{
				entry = rr.GetWString(L"cpus_unlock");
				break;
			}
			case CPUS_CREDUI:
			{
				entry = rr.GetWString(L"cpus_credui");
				break;
			}
			case CPUS_CHANGE_PASSWORD:
			case CPUS_PLAP:
			case CPUS_INVALID:
				return false;
			default:
				return false;
		}
		std::string strCaller = (caller == 0 ? "Provider" : "Filter");
		PIDebug("Checking for " + strCaller + ", " + CPUStoString(cpus) + ", " + (isRemote ? "remote" : "local")
			+ ", entry=" + Convert::ToString(entry));
		// default - no additional config found
		if (entry.empty()) return true;

		if (caller == FILTER)
		{
			// Check that we don't filter if the CP is not enumerated
			return (entry == L"0e" || (entry == L"1e" && isRemote) || (entry == L"2e" && !isRemote));
		}
		else if (caller == PROVIDER)
		{
			// 0 means fully enabled, 1-only remote, 2-non-remote, 3-disabled
			return ((entry.at(0) == L'1' && isRemote) || (entry.at(0) == L'2' && !isRemote) || (entry.at(0) == L'0'));
		}

		return false;
	}

#define TERMINAL_SERVER_KEY _T("SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\")
#define GLASS_SESSION_ID    _T("GlassSessionId")
	bool IsCurrentSessionRemote()
	{
		bool fIsRemoteable = false;
		if (GetSystemMetrics(SM_REMOTESESSION))
		{
			fIsRemoteable = true;
		}
		else
		{
			HKEY hRegKey = nullptr;
			LONG lResult;

			lResult = RegOpenKeyEx(
				HKEY_LOCAL_MACHINE,
				TERMINAL_SERVER_KEY,
				0, // ulOptions
				KEY_READ,
				&hRegKey
			);

			if (lResult == ERROR_SUCCESS)
			{
				DWORD dwGlassSessionId = 0;
				DWORD cbGlassSessionId = sizeof(dwGlassSessionId);
				DWORD dwType = 0;

				lResult = RegQueryValueEx(
					hRegKey,
					GLASS_SESSION_ID,
					NULL, // lpReserved
					&dwType,
					(BYTE*)&dwGlassSessionId,
					&cbGlassSessionId
				);

				if (lResult == ERROR_SUCCESS)
				{
					DWORD dwCurrentSessionId;

					if (ProcessIdToSessionId(GetCurrentProcessId(), &dwCurrentSessionId))
					{
						fIsRemoteable = (dwCurrentSessionId != dwGlassSessionId);
					}
				}
			}

			if (hRegKey)
			{
				RegCloseKey(hRegKey);
			}
		}

		PIDebug(fIsRemoteable ? "Session is remote" : "Session is local");

		return fIsRemoteable;
	}

	std::string CPUStoString(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
	{
		switch (cpus)
		{
			case CPUS_LOGON:
				return "CPUS_LOGON";
			case CPUS_UNLOCK_WORKSTATION:
				return "CPUS_UNLOCK_WORKSTATION";
			case CPUS_CREDUI:
				return "CPUS_CREDUI";
			case CPUS_CHANGE_PASSWORD:
				return "CPUS_CHANGE_PASSWORD";
			case CPUS_PLAP:
				return "CPUS_PLAP";
			case CPUS_INVALID:
				return "CPUS_INVALID";
			default:
				return ("Unknown CPUS: " + std::to_string(cpus));
		}
	}
}
