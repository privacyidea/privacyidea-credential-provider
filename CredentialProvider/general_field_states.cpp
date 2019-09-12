#include "general_field_states.h"
#include "Configuration.h"
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
				HRESULT hr = S_OK;
				switch (scenario)
				{
				case SCENARIO_LOGON_BASE:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairs);
					break;

				case SCENARIO_UNLOCK_BASE:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsUnlock);
					break;

				case SCENARIO_SECOND_STEP:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsSecondStep);
					break;

				case SCENARIO_CHANGE_PASSWORD:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioChangePasswordFieldStatePairs);
					break;
				case SCENARIO_UNLOCK_TWO_STEP:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsUnlockTwoStep);
					break;
				case SCENARIO_LOGON_TWO_STEP:
					hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsTwoStep);
					break;
				case SCENARIO_NO_CHANGE:
				default:
					break;
				}

				return hr;
			}

			HRESULT SetScenarioBasedTextFields(
				__inout int &largeTextFieldId,
				__inout int &smallTextFieldId,
				__in CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario
				)
			{
				switch (scenario)
				{
				case CPUS_LOGON:
				case CPUS_UNLOCK_WORKSTATION:
					largeTextFieldId = LUFI_OTP_LARGE_TEXT;
					smallTextFieldId = LUFI_OTP_SMALL_TEXT;
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
			if (Data::Provider::Get()->usage_scenario == CPUS_LOGON)
			{
				if (Configuration::Get().twoStepHideOTP) {
					return s_rgScenarioLogonUnlockFieldStatePairsTwoStep;
				}
				return s_rgScenarioLogonUnlockFieldStatePairs;
			}
			else if (Data::Provider::Get()->usage_scenario == CPUS_UNLOCK_WORKSTATION)
			{
				if (Configuration::Get().twoStepHideOTP) {
					return s_rgScenarioLogonUnlockFieldStatePairsUnlockTwoStep;
				}
				return s_rgScenarioLogonUnlockFieldStatePairsUnlock;
			}
			////

			return s_rgCredProvBaseFieldStatePairsFor[cpus];
		}

		const FIELD_STATE_PAIR* GetFieldStatePairFor(SCENARIO scenario)
		{
			switch (scenario)
			{
			case SCENARIO_LOGON_BASE:
				return s_rgScenarioLogonUnlockFieldStatePairs;
				break;

			case SCENARIO_UNLOCK_BASE:
				return s_rgScenarioLogonUnlockFieldStatePairsUnlock;
				break;

			case SCENARIO_SECOND_STEP:
				return s_rgScenarioLogonUnlockFieldStatePairsSecondStep;
				break;

			case SCENARIO_CHANGE_PASSWORD:
				return s_rgScenarioChangePasswordFieldStatePairs;
				break;

			case SCENARIO_LOGON_TWO_STEP:
				return s_rgScenarioLogonUnlockFieldStatePairsTwoStep;
				break;

			case SCENARIO_UNLOCK_TWO_STEP:
				return s_rgScenarioLogonUnlockFieldStatePairsUnlockTwoStep;
				break;

			case SCENARIO_NO_CHANGE:
			default:
				return NULL;
				break;
			}
		}
	}
}