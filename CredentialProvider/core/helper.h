#ifndef _HELPER_H
#define _HELPER_H
#pragma once

//#include "dependencies.h"

#include "common.h"
#include "data.h"
#include <stdio.h>

namespace Helper
{
	namespace Debug
	{
		#define LOGFILE_NAME "C:\\logFile.txt"

		#ifdef _DEBUG
			#define DebugPrintLn(message) Helper::Debug::PrintLn(message,__FILE__,__LINE__) 
		#else
			#define DebugPrintLn(message) UNREFERENCED_PARAMETER(message)
		#endif

		void PrintLn(const char *message, char *file, int line);
		void PrintLn(const wchar_t *message, char *file, int line);
		void PrintLn(int integer, char *file, int line);
		//void PrintLnW(const wchar_t *message, char *file, int line);
		//#define DebugPrintLnW(message) Helper::Debug::PrintLnW(message,__FILE__,__LINE__)
		void WriteLogFile(const char* szString);
		void WriteLogFile(const wchar_t* szString);
	}

	// Helper funcs
	void RedrawGUI();

	void SeparateUserAndDomainName(
		__in wchar_t *domain_slash_username,
		__out wchar_t *username,
		__in int sizeUsername,
		__out_opt wchar_t *domain,
		__in_opt int sizeDomain
		);

	int GetFirstActiveIPAddress(
		__deref_out_opt char *&ip_addr
		);

	void WideCharToChar(
		__in PWSTR data,
		__in int buffSize,
		__out char *pc
		);

	void CharToWideChar(
		__in char* data,
		__in int buffSize,
		__out PWSTR pc
		);

	size_t iso8859_1_to_utf8(char *content, size_t max_size);

	// END
}

#endif

