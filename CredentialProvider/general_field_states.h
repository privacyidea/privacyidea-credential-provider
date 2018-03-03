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
		const FIELD_STATE_PAIR* GetFieldStatePairFor(SCENARIO scenario);
	}
}

#include "general.h"

#endif