/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2019 NetKnights GmbH
** Author: Nils Behlen
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
#include "PrivacyIDEA.h"
#include "Challenge.h"
#include "Convert.h"
#include <thread>
#include <stdexcept>

using namespace std;

// Check if there is a mapping for the given domain or - if not - a default realm is set
HRESULT PrivacyIDEA::AppendRealm(std::wstring domain, std::map<std::string, std::string>& parameters)
{
	wstring realm = L"";
	try
	{
		realm = _realmMap.at(Convert::ToUpperCase(domain));
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
		parameters.try_emplace("realm", Convert::ToString(realm));
	}

	return S_OK;
}

void PrivacyIDEA::PollThread(
	const std::wstring& username,
	const std::wstring& domain,
	const std::string& transaction_id,
	std::function<void(bool)> callback)
{
	DebugPrint("Starting poll thread...");
	bool success = false;

	this_thread::sleep_for(chrono::milliseconds(300));

	while (_runPoll.load())
	{
		if (PollTransaction(transaction_id))
		{
			success = true;
			_runPoll.store(false);
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(500));
	}
	DebugPrint("Polling stopped");
	// Only finalize if there was success while polling. If the authentication finishes otherwise, the polling is stopped without finalizing.
	if (success)
	{
		DebugPrint("Finalizing transaction...");
		PIResponse pir;
		HRESULT res = ValidateCheck(username, domain, L"", pir, transaction_id);
		if (FAILED(res))
		{
			DebugPrint("/validate/check failed with " + to_string(res));
			callback(false);
		}
		else
		{
			callback(pir.value);
		}
	}
}

HRESULT PrivacyIDEA::ValidateCheck(const std::wstring& username, const std::wstring& domain,
	const std::wstring& otp, PIResponse& responseObj, const std::string& transaction_id)
{
	DebugPrint(__FUNCTION__);
	HRESULT res = S_OK;
	string strUsername = Convert::ToString(username);
	string strOTP = Convert::ToString(otp);

	map<string, string> parameters =
	{
		{ "user", strUsername },
		{ "pass", strOTP }
	};

	if (!transaction_id.empty())
	{
		parameters.try_emplace("transaction_id", transaction_id);
	}

	AppendRealm(domain, parameters);

	string response = _endpoint.SendRequest(PI_ENDPOINT_VALIDATE_CHECK, parameters, RequestMethod::POST);

	// If the response is empty, there was an error in the endpoint
	if (response.empty())
	{
		DebugPrint("Response was empty. Endpoint error: " + Convert::LongToHexString(_endpoint.GetLastErrorCode()));
		return _endpoint.GetLastErrorCode();
	}
	// Check for initial offline OTP data
	auto offlineData = _parser.ParseResponseForOfflineData(response);
	if (!offlineData.empty())
	{
		for (auto& item : offlineData)
		{
			_offlineHandler.AddOfflineData(item);
		}
	}
	res = _parser.ParsePIResponse(response, responseObj);
	return res;
}

/*!

@return PI_OFFLINE_NO_OFFLINE_DATA, PI_OFFLINE_DATA_NO_OTPS_LEFT, S_OK, E_FAIL
*/
HRESULT PrivacyIDEA::OfflineCheck(const std::wstring& username, const std::wstring& otp)
{
	DebugPrint(__FUNCTION__);
	string szUsername = Convert::ToString(username);

	HRESULT res = _offlineHandler.DataVailable(szUsername);
	if (res == S_OK)
	{
		DebugPrint("Offline data available for " + szUsername + ", verifying OTP...");
		res = _offlineHandler.VerifyOfflineOTP(otp, szUsername);
		DebugPrint("Offline verification result: " + Convert::LongToHexString(res));
	}
	else if (res == PI_OFFLINE_DATA_NO_OTPS_LEFT)
	{
		DebugPrint("No offline OTPs left for the user.");
	}
	// Do not log the case PI_OFFLINE_NO_OFFLINE_DATA, because it would spam
	return res;
}

HRESULT PrivacyIDEA::OfflineRefill(std::wstring username, std::wstring lastOTP)
{
	string refilltoken, serial;
	string szUsername = Convert::ToString(username);
	string szLastOTP = Convert::ToString(lastOTP);

	HRESULT hr = _offlineHandler.GetRefillTokenAndSerial(szUsername, refilltoken, serial);
	if (hr != S_OK)
	{
		DebugPrint("Failed to get parameters for offline refill!");
		return E_FAIL;
	}

	map<string, string> parameters = {
		{"pass", szLastOTP},
		{"refilltoken", refilltoken},
		{"serial", serial}
	};

	string response = _endpoint.SendRequest(PI_ENDPOINT_OFFLINE_REFILL, parameters, RequestMethod::POST);

	if (response.empty())
	{
		DebugPrint("Offline refill response was empty");
		return _endpoint.GetLastErrorCode();
	}

	OfflineData data;
	hr = _parser.ParseRefillResponse(response, szUsername, data);
	_offlineHandler.AddOfflineData(data);
	return hr;
}

size_t PrivacyIDEA::GetOfflineOTPCount(const std::wstring& username)
{
	return _offlineHandler.GetOfflineOTPCount(Convert::ToString(username));
}

bool PrivacyIDEA::StopPoll()
{
	DebugPrint("Stopping poll thread...");
	_runPoll.store(false);
	return true;
}

void PrivacyIDEA::PollTransactionAsync(std::wstring username, std::wstring domain, std::string transaction_id, std::function<void(bool)> callback)
{
	_runPoll.store(true);
	std::thread t(&PrivacyIDEA::PollThread, this, username, domain, transaction_id, callback);
	t.detach();
}

bool PrivacyIDEA::PollTransaction(std::string transaction_id)
{
	map<string, string> parameters = {
		{"transaction_id", transaction_id }
	};

	string response = _endpoint.SendRequest(PI_ENDPOINT_POLLTRANSACTION, parameters, RequestMethod::GET);
	return _parser.ParsePollTransaction(response);
}
