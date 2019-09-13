#pragma once
#include <string>
#include <codecvt>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

#define DbgRelPrintLn(message) Logger::Get().log(message, __FILENAME__, __LINE__, true)
#define DebugPrintLn(message) Logger::Get().log(message, __FILENAME__, __LINE__, false)

class Logger
{
public:
	Logger(Logger const&) = delete;
	void operator=(Logger const&) = delete;

	static Logger& Get() {
		static Logger instance;
		return instance;
	}

	void log(const char* message, const char* file, int line, bool logInProduction);

	void log(const wchar_t* message, const char* file, int line, bool logInProduction);

	void log(int message, const char* file, int line, bool logInProduction);

private:
	Logger();

	void logS(std::string message, const char* file, int line, bool logInProduction);

	void logW(std::wstring message, const char* file, int line, bool logInProduction);

	bool releaseLog;

	std::string logfilePathDebug = "C:\\privacyIDEACPDebugLog.txt";
	std::string logfilePathProduction = "C:\\privacyIDEACredentialProviderLog.txt";
};
