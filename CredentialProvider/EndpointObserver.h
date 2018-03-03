#ifndef _ENDPOINTOBSERVER_H
#define _ENDPOINTOBSERVER_H
#pragma once

#include "common.h"

#include "endpoint.h"

//#include "CCredential.h"

namespace EndpointObserver
{
	struct FLAGS
	{
		bool RedrawGUI = false;
		bool Exit = false;
	};

	struct RESULT
	{
		DWORD returnValue;
	};

	FLAGS*& Flags();
	RESULT*& Result();

	void Default();
	void Init();
	void Deinint();

	namespace Thread
	{
		#define EPT_SUCCESS 0
		#define EPT_FAILURE 1
		#define EPT_UNKNOWN (DWORD)-1

		#define FREQUENCY_IN_MSEC 1000

		enum STATUS
		{
			RUNNING,
			NOT_RUNNING,
			FINISHED
		};

		static HANDLE Handle = NULL;
		static STATUS Status = STATUS::NOT_RUNNING;
		static bool ShutdownNow = false;

		HANDLE GetHandle();
		STATUS GetStatus();

		void Shutdown();

		void Create(LPVOID lpParamter);
		void Destroy();

		DWORD WINAPI Run(LPVOID lpParameter);
	}

	namespace Concrete
	{
		HRESULT CheckEndpoint();
	}
}

#endif