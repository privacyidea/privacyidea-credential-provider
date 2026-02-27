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
#include "Configuration.h"
#include "Logger.h"
#include <scenario.h>
#include <memory>
#include <Windows.h>
#include <wincred.h>

constexpr auto CLEAR_FIELDS_CRYPT = 0;
constexpr auto CLEAR_FIELDS_EDIT_AND_CRYPT = 1;
constexpr auto CLEAR_FIELDS_ALL = 2;
constexpr auto CLEAR_FIELDS_ALL_DESTROY = 3;

constexpr auto MAX_SIZE_DOMAIN = 64;
constexpr auto MAX_SIZE_USERNAME = 512;

class Utilities
{
public:
	Utilities(std::shared_ptr<Configuration> c) noexcept;

	HRESULT KerberosLogon(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in std::wstring password,
		__in std::wstring domain
	);

	HRESULT KerberosChangePassword(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__in std::wstring username,
		__in std::wstring passwordOld,
		__in std::wstring passwordNew,
		__in std::wstring domain
	);

	HRESULT CredPackAuthentication(
		__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
		__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in std::wstring username,
		__in std::wstring password,
		__in std::wstring domain
	);

	HRESULT Clear(
		wchar_t* (&field_strings)[FID_NUM_FIELDS],
		CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR (&pcpfd)[FID_NUM_FIELDS],
		ICredentialProviderCredential* pcpc,
		ICredentialProviderCredentialEvents* pcpce,
		char clear
	);

	HRESULT SetFieldStatePairBatch(
		__in ICredentialProviderCredential* self,
		__in ICredentialProviderCredentialEvents* pCPCE,
		__in const FIELD_STATE_PAIR* pFSP
	);

	HRESULT InitializeField(
		LPWSTR rgFieldStrings[FID_NUM_FIELDS],
		DWORD fieldIndex
	);

	static std::wstring ComputerName();

	/// <summary>
	/// Split the input into user and domain. The possible formats are: domain\user and user@domain, check in that order.
	/// If no '\' or '@' exsists in the input, the whole input is assumed to be the username.
	/// If the domain is '.', it will be resolved to the local computer name.
	/// </summary>
	/// <param name="input"></param>
	/// <param name="username"></param>
	/// <param name="domain"></param>
	static void SplitUserAndDomain(const std::wstring& input, std::wstring& username, std::wstring& domain);

	/// <summary>
	/// Check if the input is an UPN. The check is very basic and assumes the input is an UPN if it contains an @ and no \.
	/// </summary>
	/// <param name="input"></param>
	/// <param name="config"></param>
	/// <returns>bool if upn detected, false otherwise</returns>
	static bool CheckForUPN(const std::wstring& input) noexcept;
	
	HRESULT CopyInputFields();

	HRESULT CopyUsernameField();

	HRESULT CopyPasswordField();

	HRESULT CopyOTPField();

	HRESULT CopyWANPinField();

	HRESULT CopyPasswordChangeFields();

private:
	std::shared_ptr<Configuration> _config;
};

