//#include "common_comboboxes.h"

#define WORKSTATION_LOCKED Data::Credential::Get()->user_name

#include "scenario_unlock_logon.h"
#include "scenario_change_password.h"
#include "scenario_credui.h"

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* s_rgCredProvFieldDescriptorsFor[] =
{
	NULL,												// CPUS_INVALID = 0x0000,
	s_rgScenarioLogonUnlockCredProvFieldDescriptors,	// CPUS_LOGON,
	s_rgScenarioLogonUnlockCredProvFieldDescriptors,	// CPUS_UNLOCK_WORKSTATION,
	s_rgScenarioChangePasswordCredProvFieldDescriptors,	// CPUS_CHANGE_PASSWORD,
	s_rgScenarioCredUiCredProvFieldDescriptors,			// CPUS_CREDUI,
	NULL												// CPUS_PLAP
};

static const FIELD_INITIALIZOR* s_rgCredProvFieldInitializorsFor[] =
{
	NULL,											// CPUS_INVALID = 0x0000,
	s_rgScenarioLogonUnlockFieldInitializors,		// CPUS_LOGON,
	s_rgScenarioLogonUnlockFieldInitializors,		// CPUS_UNLOCK_WORKSTATION,
	s_rgScenarioChangePasswordFieldInitializors,	// CPUS_CHANGE_PASSWORD,
	s_rgScenarioCredUiFieldInitializors,			// CPUS_CREDUI,
	NULL											// CPUS_PLAP
};

static const unsigned int s_rgCredProvNumFieldsFor[] =
{
	0,					// CPUS_INVALID = 0x0000,
	LUFI_NUM_FIELDS,	// CPUS_LOGON,
	LUFI_NUM_FIELDS,	// CPUS_UNLOCK_WORKSTATION,
	CPFI_NUM_FIELDS,	// CPUS_CHANGE_PASSWORD,
	CFI_NUM_FIELDS,		// CPUS_CREDUI,
	0					// CPUS_PLAP
};

static const FIELD_STATE_PAIR* s_rgCredProvBaseFieldStatePairsFor[] =
{
	NULL,												// CPUS_INVALID = 0x0000,
	s_rgScenarioLogonUnlockFieldStatePairs,				// CPUS_LOGON,
	s_rgScenarioLogonUnlockFieldStatePairsUnlock,		// CPUS_UNLOCK_WORKSTATION,
	s_rgScenarioChangePasswordFieldStatePairs,			// CPUS_CHANGE_PASSWORD,
	s_rgScenarioCredUiFieldStatePairs,					// CPUS_CREDUI,
	NULL												// CPUS_PLAP
};