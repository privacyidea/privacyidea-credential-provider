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

#ifndef _GENERAL_FIELD_STATES_H
#define _GENERAL_FIELD_STATES_H
#pragma once

#include "common.h"

namespace General
{
	namespace Fields
	{
		enum SCENARIO
		{
			SCENARIO_NO_CHANGE = 0,
			SCENARIO_LOGON_BASE = 1,
			SCENARIO_UNLOCK_BASE = 2,
			SCENARIO_SECOND_STEP = 3,
			SCENARIO_LOGON_TWO_STEP = 4,
			SCENARIO_UNLOCK_TWO_STEP = 5,
			SCENARIO_CHANGE_PASSWORD = 6,
		};

		namespace Helpers
		{

			HRESULT SetScenarioBasedFieldStates(
				__in ICredentialProviderCredential* self,
				__in ICredentialProviderCredentialEvents* pCPCE,
				__in SCENARIO scenario
				);

			HRESULT SetScenarioBasedTextFields(
				__inout int &largeTextFieldId,
				__inout int &smallTextFieldId,
				__in CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario
				);
		}

		const FIELD_STATE_PAIR* GetFieldStatePairFor(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);
	}
}

#include "general.h"

#endif