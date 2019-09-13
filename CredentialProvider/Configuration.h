#pragma once
#include <string>

class Configuration
{
public:
	Configuration(Configuration const&) = delete;
	void operator=(Configuration const&) = delete;

	static Configuration& Get() {
		static Configuration instance;
		return instance;
	}

	void PrintConfig();

	std::wstring hostname;
	std::wstring path;
	std::wstring loginText;
	std::wstring otpText;
	std::wstring bitmapPath;

	bool twoStepHideOTP;
	bool twoStepSendPassword;
	bool twoStepSendEmptyPassword;

	bool sslIgnoreCA;
	bool sslIgnoreCN;

	bool hideFullName;
	bool hideDomainName;

	bool releaseLog;
	bool logSensitive;

	bool noDefault;

	int customPort;
	int hide_otp_sleep_s;

	int winVerMajor;
	int winVerMinor;
	int winBuildNr;

private:
	Configuration();

	void loadConfig();
	std::wstring getRegistry(std::wstring name);
	bool getBoolRegistry(std::wstring name);
};