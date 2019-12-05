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

#include "general_field_states.h"
#include "Configuration.h"
#include "Logger.h"
#include <new_unlock_scenario.h>

namespace General
{
	namespace Fields
	{
		namespace Helpers
		{
			HRESULT SetScenarioBasedFieldStates(
				__in ICredentialProviderCredential* self,
				__in ICredentialProviderCredentialEvents* pCPCE,
				__in SCENARIO scenario
			)
			{
				DebugPrintLn("Setting fields for scenario: " + std::to_string(scenario));
				HRESULT hr = S_OK;
				switch (scenario)
				{
				case SCENARIO_LOGON_BASE:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioPushFieldStatePairs);
					break;

				case SCENARIO_UNLOCK_BASE:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioPushFieldStatePairsUnlock);
					break;

				case SCENARIO_SECOND_STEP:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioPushFieldStatePairsTwoStepSecondStep);
					break;

				case SCENARIO_CHANGE_PASSWORD:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioChangePasswordFieldStatePairs);
					break;
				case SCENARIO_UNLOCK_TWO_STEP:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioPushFieldStatePairsUnlockTwoStep);
					break;
				case SCENARIO_LOGON_TWO_STEP:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioPushFieldStatePairsTwoStep);
					break;
				case SCENARIO_NO_CHANGE:
				default:
					break;
				}

				return hr;
			}

			HRESULT SetScenarioBasedTextFields(
				__inout int& largeTextFieldId,
				__inout int& smallTextFieldId,
				__in CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario
			)
			{
				switch (scenario)
				{
				case CPUS_LOGON:
				case CPUS_UNLOCK_WORKSTATION:
					largeTextFieldId = LPFI_OTP_LARGE_TEXT;
					smallTextFieldId = LPFI_OTP_SMALL_TEXT;
					break;
				case CPUS_CHANGE_PASSWORD:
					largeTextFieldId = CPFI_OTP_LARGE_TEXT;
					smallTextFieldId = CPFI_OTP_SMALL_TEXT;
					break;
				case CPUS_CREDUI:
					largeTextFieldId = CFI_OTP_LARGE_TEXT;
					smallTextFieldId = CFI_OTP_SMALL_TEXT;
					break;
				default:
					break;
				}

				return S_OK;
			}
		}

		const FIELD_STATE_PAIR* GetFieldStatePairFor(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
		{
			//// CONCRETE
			if (Configuration::Get().provider.usage_scenario == CPUS_LOGON)
			{
				if (Configuration::Get().twoStepHideOTP)
				{
					return s_rgScenarioPushFieldStatePairsTwoStep;
				}
				return s_rgScenarioPushFieldStatePairs;
			}
			else if (Configuration::Get().provider.usage_scenario == CPUS_UNLOCK_WORKSTATION)
			{
				if (Configuration::Get().twoStepHideOTP)
				{
					return s_rgScenarioLogonUnlockFieldStatePairsUnlockTwoStep;
				}
				return s_rgScenarioLogonUnlockFieldStatePairsUnlock;
			}
			return s_rgScenarioPushFieldStatePairs;
		}
	}
}