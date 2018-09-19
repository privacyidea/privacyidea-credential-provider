#include "data.h"

namespace Data
{

	namespace Gui
	{

		GUI*& Get()
		{
			static struct GUI *data = NULL;

			return data;
		}

		void Default()
		{
			struct GUI*& data = Get();

			if (data == NULL)
				return;

			ZERO(data->user_name);
			ZERO(data->domain_name);
			ZERO(data->ldap_pass);

			ZERO(data->otp_pass);

			ZERO(data->ldap_pass_new_1);
			ZERO(data->ldap_pass_new_2);
			
			data->use_offline_pass = false;
		}

		void Init()
		{
			struct GUI*& data = Get();
			
			if (data == NULL)
				data = (struct GUI*) malloc(sizeof(struct GUI));

			Default();
		}

		void Deinit()
		{
			struct GUI*& data = Get();

			Default();

			if (data != NULL)
			{
				free(data);
				data = NULL;
			}
		}

	} // Namespace Gui

	namespace Provider
	{

		PROVIDER*& Get()
		{
			static struct PROVIDER *data = NULL;

			return data;
		}

		void Default()
		{
			struct PROVIDER*& data = Get();

			if (data == NULL)
				return;

			data->_pcpe = NULL;
			data->_upAdviseContext = NULL;
			data->credPackFlags = 0;
		}

		void Init()
		{
			struct PROVIDER*& data = Get();

			data = (struct PROVIDER*) malloc(sizeof(struct PROVIDER));

			Default();
		}

		void Deinit()
		{
			struct PROVIDER*& data = Get();

			Default();

			free(data);
			data = NULL;
		}

	} // Namespace Provider

	namespace Credential
	{

		CREDENTIAL*& Get()
		{
			static struct CREDENTIAL *data = NULL;

			return data;
		}

		void Default()
		{
			struct CREDENTIAL*& data = Get();

			if (data == NULL)
				return;

			data->user_name = NULL;
			data->domain_name = NULL;
			data->password = NULL;

			data->pqcws = NULL;
			data->userCanceled = false;
			data->endpointStatus = E_NOT_SET;

			data->passwordMustChange = false;
			data->passwordChanged = false;

			ZERO(data->tx_id);
			ZERO(data->serial);
		}

		void Init()
		{
			struct CREDENTIAL*& data = Get();

			data = (struct CREDENTIAL*) malloc(sizeof(struct CREDENTIAL));

			Default();
		}

		void Deinit()
		{
			struct CREDENTIAL*& data = Get();

			Default();

			free(data);
			data = NULL;
		}

	} // Namespace Credential

	namespace General
	{
		GENERAL*& Get()
		{
			static struct GENERAL *data = NULL;

			return data;
		}

		void Default()
		{
			struct GENERAL*& data = Get();

			if (data == NULL)
				return;

			data->startEndpointObserver = false;
			data->bypassEndpoint = false;
			data->bypassDataInitialization = false;
			data->bypassDataDeinitialization = false;
			data->clearFields = true;
		}

		void Init()
		{
			DebugPrintLn(__FUNCTION__);

			struct GENERAL*& data = Get();

			if (data == NULL)
			{
				data = (struct GENERAL*) malloc(sizeof(struct GENERAL));
			}

			Default();
		}

		void Deinit()
		{
			DebugPrintLn(__FUNCTION__);

			struct GENERAL*& data = Get();

			Default();

			if (data != NULL)
			{
				free(data);
				data = NULL;
			}
		}
	} // Namespace General

} // Namespace Data