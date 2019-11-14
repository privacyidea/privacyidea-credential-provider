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

#ifndef _DATA_H
#define _DATA_H
#pragma once

#include "common.h"
#include "helper.h"

#define MAX_BUFFER_SIZE_PASSWORD 2048
#define MAX_BUFFER_SIZE_NAMES 256

namespace Data
{	
	namespace Gui
	{
		struct GUI
		{
			// General:
			wchar_t user_name[MAX_BUFFER_SIZE_NAMES];
			wchar_t domain_name[MAX_BUFFER_SIZE_NAMES];
			wchar_t ldap_pass[MAX_BUFFER_SIZE_PASSWORD];

			// LogonUnlock:
			wchar_t otp_pass[MAX_BUFFER_SIZE_NAMES];
			bool use_offline_pass;

			// ChangePassword:
			wchar_t ldap_pass_new_1[MAX_BUFFER_SIZE_PASSWORD];
			wchar_t ldap_pass_new_2[MAX_BUFFER_SIZE_PASSWORD];
		};

		GUI*& Get();
		void Init();
		void Deinit();
		void Default();
	}

	namespace Provider
	{
		struct PROVIDER
		{
			ICredentialProviderEvents* _pcpe;
			UINT_PTR _upAdviseContext;

			CREDENTIAL_PROVIDER_USAGE_SCENARIO usage_scenario;
			DWORD credPackFlags;
		};

		PROVIDER*& Get();
		void Init();
		void Deinit();
	}

	namespace Credential
	{
		struct CREDENTIAL
		{
			PWSTR user_name;
			PWSTR domain_name;
			PWSTR password;
			
			IQueryContinueWithStatus* pqcws = NULL;
			bool userCanceled = false;
			HRESULT endpointStatus = E_FAIL;

			bool passwordMustChange = false;
			bool passwordChanged = false;

			// Challenge Response
			char tx_id[64];
			char serial[64];
			char message[256];
		};

		CREDENTIAL*& Get();
		void Init();
		void Deinit();
		void Default();
	}

	namespace General
	{
		struct GENERAL
		{
			bool startEndpointObserver = false;
			bool bypassEndpoint = false;
			bool bypassDataInitialization = false;
			bool bypassDataDeinitialization = false;
			bool clearFields = true;
		};

		GENERAL*& Get();
		void Init();
		void Deinit();
		void Default();
	}
}

#endif