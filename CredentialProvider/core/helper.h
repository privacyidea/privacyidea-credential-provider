#ifndef _HELPER_H
#define _HELPER_H
#pragma once

//#include "dependencies.h"

#include "common.h"
#include "data.h"
#include <stdio.h>
#include <tchar.h>
#include <chrono>
#include <ctime>
#include <string>
#include <codecvt>
#include <locale>

namespace Helper
{
	namespace Debug
	{
#define PROD_LOGFILE_NAME "C:\\privacyIDEAReleaseLogFile.txt"
#define LOGFILE_NAME "C:\\privacyIDEADebugLogFile.txt"

#ifdef _DEBUG
#define DebugPrintLn(message) Helper::Debug::PrintLn(message,__FILE__,__LINE__) 
//#define //writeToLog(message) UNREFERENCED_PARAMETER(message)
#else
#define DebugPrintLn(message) UNREFERENCED_PARAMETER(message)
//#define //writeToLog(message) Helper::Debug::PrintLn(message,__FILE__,__LINE__) 
#endif

		void PrintBase(char *file, char *code);
		void PrintLn(const char *message, char *file, int line);
		void PrintLn(const wchar_t *message, char *file, int line);
		void PrintLn(int integer, char *file, int line);
		void WriteLogFile(const char* szString);
		void WriteLogFile(const wchar_t* szString);
	}

	// Helper funcs
	void RedrawGUI();

	std::wstring s2ws(const std::string& str);
	std::string ws2s(const std::wstring& wstr);

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

