#include "PrivacyIDEA.h"
#include "Challenge.h"
#include <codecvt>
#include <thread>
#include <sstream>

using namespace std;

// Check if there is a mapping for the given domain or - if not - a default realm is set
HRESULT PrivacyIDEA::AppendRealm(std::wstring domain, std::string& data)
{
	wstring realm = L"";
	try
	{
		realm = _realmMap.at(UpperCase(domain));
	}
	catch (const std::out_of_range& e)
	{
		UNREFERENCED_PARAMETER(e);
		// no mapping - if default domain exists use that
		if (!_defaultRealm.empty())
		{
			realm = _defaultRealm;
		}
	}

	if (!realm.empty())
	{
		data += "&" + _endpoint.EncodePair("realm", ws2s(realm));
	}

	return S_OK;
}

void PrivacyIDEA::PollThread(
	const std::string& transaction_id,
	const std::string& username,
	std::function<void(bool)> callback)
{
	DebugPrint("Starting poll thread...");
	HRESULT res = E_FAIL;
	bool success = false;
	std::string data = _endpoint.EncodePair("transaction_id", transaction_id);
	while (_runPoll.load())
	{
		string response = _endpoint.SendRequest(PI_ENDPOINT_POLL_TX, data, RequestMethod::GET);
		res = _endpoint.ParseForTransactionSuccess(response);
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
			HRESULT result = _endpoint.FinalizePolling(username, transaction_id);
			callback((result == PI_AUTH_SUCCESS));
		}
		catch (const std::out_of_range& e)
		{
			UNREFERENCED_PARAMETER(e);
			DebugPrint("Could not get transaction id to finialize");
			callback(false);
		}
	}
}

HRESULT PrivacyIDEA::TryOfflineRefill(std::string username, std::string lastOTP)
{
	std::string data = _endpoint.EncodePair("pass", lastOTP);
	string refilltoken, serial;
	HRESULT hr = _offlineHandler.GetRefillTokenAndSerial(username, refilltoken, serial);
	if (hr != S_OK)
	{
		DebugPrint("Failed to get parameters for offline refill!");
		return E_FAIL;
	}

	data += "&" + _endpoint.EncodePair("refilltoken", refilltoken)
		+ "&" + _endpoint.EncodePair("serial", serial);
	string response = _endpoint.SendRequest(PI_ENDPOINT_OFFLINE_REFILL, data, RequestMethod::POST);

	if (response.empty())
	{
		DebugPrint("Offline refill response was empty");
		return E_FAIL;
	}

	HRESULT res = _offlineHandler.ParseRefillResponse(response, username);

	return res;
}

HRESULT PrivacyIDEA::ValidateCheck(const std::wstring& username, const std::wstring& domain,
	const std::wstring& otp, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	HRESULT piStatus = E_FAIL;
	HRESULT ret = PI_AUTH_FAILURE;
	HRESULT offlineStatus = E_FAIL;
	std::wstring otp2(otp.c_str());
	string strUsername = ws2s(username);

	// Check if offline otp available
	if (_offlineHandler.DataVailable(strUsername) == S_OK)
	{
		DebugPrint("Offline data available");
		offlineStatus = _offlineHandler.VerifyOfflineOTP(otp, strUsername);
		if (offlineStatus == S_OK)
		{
			// try refill then return
			DebugPrint("Offline authentication successful");
			offlineStatus = TryOfflineRefill(strUsername, ws2s(otp));
			if (offlineStatus != S_OK)
			{
				Print("Offline refill failed: " + LongToHexString(offlineStatus));
			}
			return PI_AUTH_SUCCESS;	// Still return SUCCESS because offline authentication was successful
		}
		else
		{
			// Continue with other steps
			offlineStatus = PI_OFFLINE_WRONG_OTP;
			Print("Offline data was available, but authenticiation failed");
		}
	}
	else if (offlineStatus == PI_OFFLINE_DATA_NO_OTPS_LEFT)
	{
		DebugPrint("No offline OTPs left for the user.");
	}

	// Connect to the privacyIDEA Server
	std::string data = _endpoint.EncodePair("user", ws2s(username)) + "&" + _endpoint.EncodePair("pass", otp);

	if (!transaction_id.empty())
	{
		data += "&" + _endpoint.EncodePair("transaction_id", transaction_id);
	}

	AppendRealm(domain, data);

	string response = _endpoint.SendRequest(PI_ENDPOINT_VALIDATE_CHECK, data, RequestMethod::POST);

	// If the response is empty, there was an error in the endpoint
	if (response.empty())
	{
		HRESULT epCode = _endpoint.GetLastErrorCode();
		DebugPrint("Response was empty. Endpoint error: " + LongToHexString(epCode));
		// If offline was available, give the hint that the entered OTP might be wrong
		if (offlineStatus == PI_OFFLINE_WRONG_OTP && epCode == PI_ENDPOINT_SERVER_UNAVAILABLE)
		{
			return PI_WRONG_OFFLINE_SERVER_UNAVAILABLE;
		}

		// otherwise return PI_ENDPOINT_SERVER_UNAVAILABLE or PI_ENDPOINT_SETUP_ERROR
		return epCode;
	}

	// Check if the response contains an error, message and code will be set
	if (_endpoint.ParseForError(response, _lastErrorMessage, _lastError) == PI_JSON_ERROR_CONTAINED)
	{
		return PI_AUTH_ERROR;
	}

	// Check for initial offline OTP data
	piStatus = _offlineHandler.ParseForOfflineData(response);
	if (piStatus == S_OK) // Data was found
	{
		// Continue
	}
	else if (piStatus == PI_OFFLINE_NO_OFFLINE_DATA)
	{
		// Continue
	}
	else
	{
		// ERROR
	}
	// Check for triggered challenge response transactions
	Challenge c;
	piStatus = _endpoint.ParseTriggerRequest(response, c);
	if (piStatus == PI_TRIGGERED_CHALLENGE)
	{
		// Check the challenge data 
		if (c.serial.empty() || c.transaction_id.empty() || c.tta == TTA::NOT_SET)
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
	piStatus = _endpoint.ParseAuthenticationRequest(response);
	if (piStatus == PI_AUTH_SUCCESS)
	{
		ret = PI_AUTH_SUCCESS;
	}
	else
	{
		// If a challenge was triggered, parsing for authentication fails, so check here if a challenge was triggered
		if (ret != PI_TRIGGERED_CHALLENGE)
		{
			if (piStatus == PI_JSON_ERROR_CONTAINED)
			{
				ret = PI_AUTH_ERROR;
			}
			else if (piStatus == PI_AUTH_FAILURE)
			{
				ret = PI_AUTH_FAILURE;
			}
		}
	}

	return ret;
}

bool PrivacyIDEA::StopPoll()
{
	DebugPrint("Stopping poll thread...");
	_runPoll.store(false);
	return true;
}

void PrivacyIDEA::AsyncPollTransaction(std::string username, std::string transaction_id, std::function<void(bool)> callback)
{
	_runPoll.store(true);
	std::thread t(&PrivacyIDEA::PollThread, this, transaction_id, username, callback);
	t.detach();
}

HRESULT PrivacyIDEA::PollTransaction(std::string transaction_id)
{
	return _endpoint.PollForTransaction(_endpoint.EncodePair("transaction_id", transaction_id));
}

bool PrivacyIDEA::OfflineDataAvailable(const std::wstring& username)
{
	return _offlineHandler.DataVailable(ws2s(username)) == S_OK;
}

Challenge PrivacyIDEA::GetCurrentChallenge()
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

std::wstring PrivacyIDEA::UpperCase(std::wstring s)
{
	std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return static_cast<wchar_t>(std::toupper(c)); });
	return s;
}

std::string PrivacyIDEA::LongToHexString(long in)
{
	std::stringstream ss;
	ss << "0x" << std::hex << in;
	return std::string(ss.str());
}

int PrivacyIDEA::GetLastError()
{
	return _lastError;
}

std::wstring PrivacyIDEA::GetLastErrorMessage()
{
	return s2ws(_lastErrorMessage);
}
