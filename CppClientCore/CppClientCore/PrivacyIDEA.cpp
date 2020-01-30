#include "PrivacyIDEA.h"
#include "Challenge.h"
#include <codecvt>
#include <thread>

using namespace std;

PrivacyIDEA& PrivacyIDEA::operator=(const PrivacyIDEA& privacyIDEA)
{
	this->_currentChallenge = privacyIDEA._currentChallenge;
	this->_defaultRealm = privacyIDEA._defaultRealm;
	this->_endpoint = privacyIDEA._endpoint;
	this->_logPasswords = privacyIDEA._logPasswords;
	this->_offlineHandler = privacyIDEA._offlineHandler;
	this->_realmMap = privacyIDEA._realmMap;
	return *this;
}

// Check if there is a mapping for the given domain or - if not - a default realm is set
HRESULT PrivacyIDEA::checkForRealm(std::map<std::string, std::string>& map, std::string domain)
{
	wstring realm = L"";
	try
	{
		realm = _realmMap.at(s2ws(domain));
	}
	catch (const std::out_of_range & e)
	{
		UNREFERENCED_PARAMETER(e);
		// no mapping - if default domain exists use that
		if (_defaultRealm.empty())
		{
			realm = _defaultRealm;
		}
	}

	if (!realm.empty())
	{
		map.try_emplace("realm", ws2s(realm));
	}

	return S_OK;
}

void PrivacyIDEA::pollThread(const std::map<std::string, std::string>& params, const std::string& username, std::function<void(bool)> callback)
{
	DebugPrint("Running poll thread...");
	HRESULT res = E_FAIL;
	bool success = false;
	while (_runPoll.load())
	{
		string response = _endpoint.connect(PI_ENDPOINT_POLL_TX, params, RequestMethod::GET);
		res = _endpoint.parseForTransactionSuccess(response);
		if (res == PI_TRANSACTION_SUCCESS)
		{
			success = true;
			_runPoll.store(false);
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(500));
	}
	DebugPrint("Polling stopped");
	if (success)
	{
		try
		{
			DebugPrint("Finalizing transaction...");
			string transaction_id = params.at("transaction_id");
			HRESULT result = _endpoint.finalizePolling(username, transaction_id);
			callback((result == PI_AUTH_SUCCESS));
		}
		catch (const std::out_of_range & e)
		{
			UNREFERENCED_PARAMETER(e);
			DebugPrint("Could not get transaction id to finialize");
			callback(false);
		}
	}
}

HRESULT PrivacyIDEA::tryOfflineRefill(std::string username, std::string lastOTP)
{
	map<string, string> params = map<string, string>();
	params.try_emplace("pass", lastOTP);
	_offlineHandler.getRefillTokenAndSerial(username, params);
	try
	{
		string refilltoken = params.at("refilltoken");
		string serial = params.at("serial");
		if (refilltoken.empty() || serial.empty())
		{
			DebugPrint("Offline refill params were empty");
			return E_FAIL;
		}
	}
	catch (const std::out_of_range & e)
	{
		UNREFERENCED_PARAMETER(e);
		DebugPrint("Offline refill failed, missing data for " + username);
		return E_FAIL;
	}
	string response = _endpoint.connect(PI_ENDPOINT_OFFLINE_REFILL, params, RequestMethod::POST);

	if (response.empty())
	{
		DebugPrint("Offline refill response was empty");
		return E_FAIL;
	}

	HRESULT res = _offlineHandler.parseRefillResponse(response, username);

	return res;
}

HRESULT PrivacyIDEA::validateCheck(const std::string& username, const  std::string& domain, const  std::string& otp, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	HRESULT res = E_FAIL, ret = PI_AUTH_FAILURE;

	// Check if offline otp available first
	res = _offlineHandler.isDataVailable(username);
	if (res == S_OK)
	{
		DebugPrint("Offline data available");
		res = _offlineHandler.verifyOfflineOTP(s2ws(otp), username);
		if (res == S_OK)
		{
			DebugPrint("Offline authentication successful");
			// try refill then return
			res = tryOfflineRefill(username, otp);
			if (res != S_OK)
			{
				DebugPrint("Offline refill failed: " + to_string(res));
			}
			return PI_AUTH_SUCCESS;	// Still return SUCCESS because offline authentication was successful
		}
		else
		{
			// Continue with other steps
			DebugPrint("Offline authenticiation failed");
		}
	}
	else if (res == PI_OFFLINE_DATA_NO_OTPS_LEFT)
	{
		// Also refill and continue?
		res = tryOfflineRefill(username, otp);
		if (res != S_OK)
			DebugPrint("Offline refill failed: " + to_string(res));
	}

	// Connect with the privacyIDEA Server
	map<string, string> params;
	params.try_emplace("user", username);
	params.try_emplace("pass", otp);
	
	if (!transaction_id.empty())
		params.try_emplace("transaction_id", transaction_id);
	
	checkForRealm(params, domain);

	string response = _endpoint.connect(PI_ENDPOINT_VALIDATE_CHECK, params, RequestMethod::POST);

	if (response.empty())
	{
		DebugPrint("Received empty response from server.");
		return PI_AUTH_ERROR;
	}

	// Check for initial offline OTP data
	res = _offlineHandler.parseForOfflineData(response);
	if (res == S_OK) // Data was found
	{
		// Continue
	}
	else if (res == PI_OFFLINE_NO_OFFLINE_DATA)
	{
		// Continue
	}
	else
	{
		// ERROR
	}
	// Check for triggered challenge response transactions
	Challenge c;
	res = _endpoint.parseTriggerRequest(response, c);
	if (res == PI_TRIGGERED_CHALLENGE)
	{
		// Check the challenge data 
		if (c.messagesEmpty() || c.serial.empty() || c.transaction_id.empty() || c.tta == TTA::NOT_SET)
		{
			DebugPrint("Incomplete challenge data: " + c.toString());
			ret = PI_AUTH_FAILURE;
		}
		else
		{
			_currentChallenge = c;
			ret = PI_TRIGGERED_CHALLENGE;
		}
	} // else if (res == PI_NO_CHALLENGE) {}

	// Check for normal success
	res = _endpoint.parseAuthenticationRequest(response);
	if (res == PI_AUTH_SUCCESS)
	{
		ret = PI_AUTH_SUCCESS;
	}
	else
	{
		// If a challenge was triggered, parsing for authentication fails, so check here if a challenge was triggered
		if (ret != PI_TRIGGERED_CHALLENGE)
		{
			if (res == PI_JSON_ERROR_CONTAINED)
				ret = PI_AUTH_ERROR;
			
			else if (res == PI_AUTH_FAILURE)
				ret = PI_AUTH_FAILURE;
		}
	}

	return ret;
}

HRESULT PrivacyIDEA::validateCheck(const std::wstring& username, const std::wstring& domain, const std::wstring& otp, const std::wstring& transaction_id)
{
	return validateCheck(ws2s(username), ws2s(domain), ws2s(otp), ws2s(transaction_id));
}

HRESULT PrivacyIDEA::validateCheck(const std::wstring& username, const std::wstring& domain, const std::wstring& otp)
{
	return validateCheck(ws2s(username), ws2s(domain), ws2s(otp), "");
}

HRESULT PrivacyIDEA::validateCheck(const std::string& username, const std::string& domain, const std::string& otp)
{
	return validateCheck(username, domain, otp, "");
}

bool PrivacyIDEA::stopPoll()
{
	_runPoll.store(false);
	return true;
}

void PrivacyIDEA::asyncPollTransaction(std::string username, std::string transaction_id, std::function<void(bool)> callback)
{
	map<string, string> params;
	params.try_emplace("transaction_id", transaction_id);
	_runPoll.store(true);
	std::thread t(&PrivacyIDEA::pollThread, this, params, username, callback);
	t.detach();
}

HRESULT PrivacyIDEA::pollTransaction(std::string transaction_id)
{
	map<string, string> params;
	params.try_emplace("transaction_id", transaction_id);
	return _endpoint.pollForTransaction(params);
}

bool PrivacyIDEA::isOfflineDataAvailable(const std::wstring& username)
{
	return _offlineHandler.isDataVailable(ws2s(username)) == S_OK;
}

HRESULT PrivacyIDEA::getLastErrorCode()
{
	return _endpoint.getLastErrorCode();
}

std::wstring PrivacyIDEA::getLastErrorMessage()
{
	return s2ws(_endpoint.getLastErrorMessage());
}

Challenge PrivacyIDEA::getCurrentChallenge()
{
	return _currentChallenge;
}

std::wstring PrivacyIDEA::s2ws(const std::string& s)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(s);
}

std::string PrivacyIDEA::ws2s(const std::wstring& ws)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(ws);
}
