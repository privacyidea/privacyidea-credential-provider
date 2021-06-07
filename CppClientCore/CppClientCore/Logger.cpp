/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2019 NetKnights GmbH
** Author:		Nils Behlen
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
** * * * * * * * * * * * * * * * * * * */

#include "Logger.h"
#include <Windows.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <codecvt>

using namespace std;

void Logger::LogS(const string& message, const char* file, int line, bool isDebugMessage)
{
	// Do not log debug messages if it is not enabled
	if (!logDebug && isDebugMessage)
	{
		return;
	}

	// Format: [Time] [file:line]  message
	time_t rawtime = NULL;
	struct tm* timeinfo = (tm*)CoTaskMemAlloc(sizeof(tm));
	char buffer[80];
	SecureZeroMemory(buffer, sizeof(buffer));
	if (timeinfo == nullptr)
	{
		return;
	}
	time(&rawtime);
	const errno_t err = localtime_s(timeinfo, &rawtime);
	if (err != 0)
	{
		return;
	}
	strftime(buffer, sizeof(buffer), "%d-%m-%Y %I:%M:%S", timeinfo);
	CoTaskMemFree(timeinfo);
	string fullMessage = "[" + string(buffer) + "] [" + string(file) + ":" + to_string(line) + "] " + message;

	ofstream os;
	os.open(logfilePath.c_str(), std::ios_base::app);
	os << fullMessage << endl;

#ifndef _OUTPUT_TO_COUT
	OutputDebugStringA(fullMessage.c_str());
	OutputDebugStringA("\n");
#else
	//std::cout << fullMessage << std::endl;
#endif // !_OUTPUT_TO_COUT
}

void Logger::LogW(const wstring& message, const char* file, int line, bool isDebugMessage)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	string conv = converterX.to_bytes(message);
	LogS(conv, file, line, isDebugMessage);
}

void Logger::Log(const char* message, const char* file, int line, bool isDebugMessage)
{
	string msg = "";
	if (message != nullptr && message[0] != NULL)
	{
		msg = string(message);
	}
	LogS(msg, file, line, isDebugMessage);
}

void Logger::Log(const wchar_t* message, const char* file, int line, bool isDebugMessage)
{
	wstring msg = L"";
	if (message != nullptr && message[0] != NULL)
	{
		msg = wstring(message);
	}
	LogW(msg, file, line, isDebugMessage);
}
/*
void Logger::log(const int message, const char* file, int line, bool isDebugMessage)
{
	string i = "(int) " + to_string(message);
	logS(i, file, line, isDebugMessage);
}
*/
void Logger::Log(const long message, const char* file, int line, bool isDebugMessage)
{
	string i = "(long) " + to_string(message);
	LogS(i, file, line, isDebugMessage);
}

void Logger::Log(const std::string& message, const char* file, int line, bool isDebugMessage)
{
	LogS(message, file, line, isDebugMessage);
}

void Logger::Log(const std::wstring& message, const char* file, int line, bool isDebugMessage)
{
	LogW(message, file, line, isDebugMessage);
}
/*
void Logger::log(const std::string& message, const char* file, int line, bool isDebugMessage)
{
	logS(message.c_str(), file, line, isDebugMessage);
}

void Logger::log(const std::wstring& message, const char* file, int line, bool isDebugMessage)
{
	logW(message.c_str(), file, line, isDebugMessage);
}
*/