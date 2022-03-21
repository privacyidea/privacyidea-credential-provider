/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 Nils Behlen
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

#pragma once

#include <string>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#define Print(message)				Logger::Get().Log(message, __FILENAME__, __LINE__, false)
#define DebugPrint(message)			Logger::Get().Log(message, __FILENAME__, __LINE__, true)

// Singleton logger class that writes to a file on C: and to OutputDebugString
class Logger
{
public:
	std::string logfilePath = "C:\\PICredentialProviderLog.txt";

	Logger(Logger const&) = delete;
	void operator=(Logger const&) = delete;

	static Logger& Get() {
		static Logger instance;
		return instance;
	}

	void Log(const char* message, const char* file, int line, bool isDebugMessage);

	void Log(const wchar_t* message, const char* file, int line, bool isDebugMessage);

	void Log(const long message, const char* file, int line, bool isDebugMessage);

	void Log(const std::string& message, const char* file, int line, bool isDebugMessage);

	void Log(const std::wstring& message, const char* file, int line, bool isDebugMessage);

	bool logDebug = false;

private:
	Logger() = default;

	void LogS(const std::string& message, const char* file, int line, bool isDebugMessage);

	void LogW(const std::wstring& message, const char* file, int line, bool isDebugMessage);
};
