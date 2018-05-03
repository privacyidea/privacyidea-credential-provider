#include "EndpointObserver.h"

namespace EndpointObserver
{
	FLAGS*& Flags()
	{
		//DebugPrintLn(__FUNCTION__);

		static struct FLAGS *data = NULL;
		return data;
	}

	RESULT*& Result()
	{
		//DebugPrintLn(__FUNCTION__);

		static struct RESULT *data = NULL;
		return data;
	}

	void Default()
	{
		//DebugPrintLn(__FUNCTION__);

		struct FLAGS*& flags = Flags();

		if (flags != NULL)
		{
			flags->RedrawGUI = false;
			flags->Exit = false;
		}

		struct RESULT*& result = Result();

		if (result != NULL)
		{
			result->returnValue = (DWORD)-1;
		}
	}

	void Init()
	{
		//DebugPrintLn(__FUNCTION__);

		struct FLAGS*& flags = Flags();

		if (flags == NULL)
		{
			flags = (struct FLAGS*) malloc(sizeof(struct FLAGS));
		}

		struct RESULT*& result = Result();

		if (result == NULL)
		{
			result = (struct RESULT*) malloc(sizeof(struct RESULT));
		}

		Default();
	}

	void Deinint()
	{
		//DebugPrintLn(__FUNCTION__);

		Default();

		struct FLAGS*& flags = Flags();

		if (flags != NULL)
		{
			free(flags);
			flags = NULL;
		}

		struct RESULT*& result = Result();

		if (result != NULL)
		{
			free(result);
			result = NULL;
		}
	}

	namespace Thread
	{
		HANDLE GetHandle()
		{
			return Handle;
		}

		STATUS GetStatus(){
			return Status;
		}

		void Shutdown()
		{
			ShutdownNow = true;
		}

		void Create(LPVOID lpParameter)
		{
			DebugPrintLn(__FUNCTION__);			

			Handle = CreateThread(NULL, NULL, Run, lpParameter, NULL, NULL);
		}

		void Destroy()
		{
			DebugPrintLn(__FUNCTION__);

			Handle = NULL;
			Status = STATUS::NOT_RUNNING;
		}

		DWORD WINAPI Run(LPVOID lpParameter)
		{
			DebugPrintLn(__FUNCTION__);

			////
			// No Parameters this time
			UNREFERENCED_PARAMETER(lpParameter);
			////
			// Having parameters
			//CCredential &credential = *((CCredential*)lpParameter);
			////

			Status = STATUS::RUNNING;

			ShutdownNow = false;

			DWORD retVal = (DWORD)-1;

			while (!ShutdownNow)
			{
				if (SUCCEEDED(Concrete::CheckEndpoint()))
				{
					Result()->returnValue = EPT_SUCCESS;
				}		

				if (Flags()->Exit == true)
				{
					Flags()->Exit = false;
					break;
				}

				if (Flags()->RedrawGUI == true)
				{
					Flags()->RedrawGUI = false;
					Helper::RedrawGUI();
				}

				Sleep(FREQUENCY_IN_MSEC);
			}

			Status = STATUS::FINISHED;

			if (Flags()->RedrawGUI == true)
			{
				Flags()->RedrawGUI = false;
				Helper::RedrawGUI();
			}

			DebugPrintLn("Leaving EndpointObserver");			

			return retVal;
		}
	} // Namespace Thread

	namespace Concrete
	{
		HRESULT CheckEndpoint()
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT result = E_FAIL;

#ifdef _DEBUG
			INIT_ZERO_CHAR(code, 1024);
			sprintf_s(code, sizeof(code) / sizeof(char), "BEFORE %s: %x", __FUNCTION__, Endpoint::GetLastErrorCode());
			DebugPrintLn(code);
#endif

			// NOTHING

			if (result != ENDPOINT_AUTH_CONTINUE)
			{
				Flags()->Exit = true;
				Flags()->RedrawGUI = true;
			}

#ifdef _DEBUG
			ZERO(code);
			sprintf_s(code, sizeof(code) / sizeof(char), "AFTER %s: %x", __FUNCTION__, Endpoint::GetLastErrorCode());
			DebugPrintLn(code);
#endif

			return result;
		}
	}

} // Namespace EnpointObserver