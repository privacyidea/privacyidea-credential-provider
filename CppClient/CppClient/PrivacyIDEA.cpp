/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2025 NetKnights GmbH
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
#include "FIDODevice.cpp"

using namespace std;

constexpr int POLL_THREAD_TIMEOUT_SECONDS = 300; // 5 minutes
constexpr int POLL_THREAD_SLEEP_MILLISECONDS = 500;

std::optional<FIDOSignRequest> PrivacyIDEA::GetOfflineFIDOSignRequest()
{
	std::optional<FIDOSignRequest> ret = std::nullopt;

	auto offlineData = offlineHandler.GetAllFIDOData();
	if (!offlineData.empty())
	{
		FIDOSignRequest signRequest;
		for (const auto& item : offlineData)
		{
			AllowCredential ac;
			ac.id = item.credId;
			signRequest.allowCredentials.push_back(ac);
			if (signRequest.rpId.empty())
			{
				signRequest.rpId = item.rpId;
			}
			if (signRequest.challenge.empty())
			{
				signRequest.challenge = FIDODevice::GenerateRandomAsBase64URL(OFFLINE_CHALLENGE_SIZE); // TODO
			}
		}
		ret = signRequest;
	}

	return ret;
}

// Check if there is a mapping for the given domain or - if not - a default realm is set
HRESULT PrivacyIDEA::AppendRealm(std::wstring domain, std::map<std::string, std::string>& parameters)
{
	wstring realm = L"";
	try
	{
		realm = _config.realmMap.at(Convert::ToUpperCase(domain));
	}
	catch (const std::out_of_range& e)
	{
		UNREFERENCED_PARAMETER(e);
		// no mapping - if default domain exists use that
		if (!_config.defaultRealm.empty())
		{
			realm = _config.defaultRealm;
		}
	}

	if (!realm.empty())
	{
		parameters.try_emplace("realm", Convert::ToString(realm));
	}

	return S_OK;
}

HRESULT PrivacyIDEA::EvaluateResponse(std::string response, _Inout_ PIResponse& responseObj)
{
	auto offlineData = _parser.ParseResponseForOfflineData(response);
	if (!offlineData.empty())
	{
		for (auto& item : offlineData)
		{
			offlineHandler.AddOfflineData(item);
		}
	}
	HRESULT res = _parser.ParseResponse(response, responseObj);
	return res;
}

void PrivacyIDEA::PollThread(
	const std::wstring& username,
	const std::wstring& domain,
	const std::wstring& upn,
	const std::string& transactionId,
	std::function<void(const PIResponse&)> callback)
{
	PIDebug("Starting poll thread...");
	bool success = false;
	this_thread::sleep_for(chrono::milliseconds(300));
	int maxIterations = POLL_THREAD_TIMEOUT_SECONDS * 1000 / POLL_THREAD_SLEEP_MILLISECONDS;
	while (_runPoll.load() && maxIterations)
	{
		if (PollTransaction(transactionId))
		{
			success = true;
			_runPoll.store(false);
			break;
		}
		this_thread::sleep_for(chrono::milliseconds(POLL_THREAD_SLEEP_MILLISECONDS));
		maxIterations--;
	}
	PIDebug("Polling stopped" + string((maxIterations == 0 ? " because of timeout" : "")));
	// Only finalize if there was success while polling. If the authentication finishes otherwise, the polling is stopped without finalizing.
	if (success)
	{
		PIDebug("Finalizing transaction...");
		PIResponse pir;
		HRESULT res = ValidateCheck(username, domain, L"", pir, transactionId, upn);
		if (FAILED(res))
		{
			PIDebug("/validate/check failed with " + to_string(res));
		}
		callback(pir);
	}
}

HRESULT PrivacyIDEA::ValidateCheck(
	const std::wstring& username,
	const std::wstring& domain,
	const std::wstring& otp,
	PIResponse& responseObj,
	const std::string& transactionId,
	const std::wstring& upn,
	const std::map<std::string, std::string>& headers)
{
	PIDebug(__FUNCTION__);
	string strOTP = Convert::ToString(otp);

	map<string, string> parameters =
	{
		{ "pass", strOTP }
	};

	// Username+Domain/Realm or just UPN
	if (_config.sendUPN && !upn.empty())
	{
		string strUPN = Convert::ToString(upn);
		PIDebug("Sending UPN " + strUPN);
		parameters.try_emplace("user", strUPN);
	}
	else
	{
		string strUsername = Convert::ToString(username);
		parameters.try_emplace("user", strUsername);
		AppendRealm(domain, parameters);
	}

	if (!transactionId.empty())
	{
		parameters.try_emplace("transaction_id", transactionId);
	}
	string response = SendRequestWithFallback(PI_ENDPOINT_VALIDATE_CHECK, parameters, headers, RequestMethod::POST);

	// If the response is empty, there was an error in the endpoint
	if (response.empty())
	{
		PIDebug("Response was empty. Endpoint error: " + Convert::LongToHexString(_endpoint.GetLastErrorCode()));
		return _endpoint.GetLastErrorCode();
	}

	return EvaluateResponse(response, responseObj);
}

std::string PrivacyIDEA::SendRequestWithFallback(
	const std::string& endpoint,
	const std::map<std::string, std::string>& parameters,
	const std::map<std::string, std::string>& headers,
	RequestMethod method)
{
	std::string response = _endpoint.SendRequest(endpoint, parameters, headers, method);

	// Just check for hostname since path and port are optional
	if (response.empty() && !_config.fallbackHostname.empty() && _endpoint.hostname != _config.fallbackHostname)
	{
		PIError(L"Primary host failed to respond, switching to fallback host: " + _config.fallbackHostname + L" for the rest of the authentication.");
		_endpoint.hostname = _config.fallbackHostname;
		_endpoint.path = _config.fallbackPath;
		_endpoint.port = _config.fallbackPort;
		response = _endpoint.SendRequest(endpoint, parameters, headers, method);
	}
	return response;
}

HRESULT PrivacyIDEA::ValidateCheckFIDO(const std::wstring& username,
	const std::wstring& domain, const FIDOSignResponse& fidoSignResponse,
	const std::string& origin,
	PIResponse& responseObj,
	const std::string& transactionId,
	const std::wstring& upn)
{
	map<string, string> parameters = { { "pass", "" } };

	// Username+Domain/Realm or just UPN
	if (_config.sendUPN && !upn.empty())
	{
		string strUPN = Convert::ToString(upn);
		PIDebug("Sending UPN " + strUPN);
		parameters.try_emplace("user", strUPN);
	}
	else
	{
		if (!username.empty())
		{
			string strUsername = Convert::ToString(username);
			parameters.try_emplace("user", strUsername);
		}

		AppendRealm(domain, parameters);
	}

	if (!transactionId.empty())
	{
		parameters.try_emplace("transaction_id", transactionId);
	}
	else
	{
		PIError("Unable to send FIDOSignResponse without transactionId!");
		return PI_ERROR_WRONG_PARAMETER;
	}

	// Add FIDO parameters, each member of the response is a parameter
	parameters.try_emplace("credentialid", fidoSignResponse.credentialid);
	parameters.try_emplace("clientdata", fidoSignResponse.clientdata);
	parameters.try_emplace("signaturedata", fidoSignResponse.signaturedata);
	parameters.try_emplace("authenticatordata", fidoSignResponse.authenticatordata);

	// TODO userhandle, exstensions

	map<string, string> headers = { { "Origin", origin } };

	string response = SendRequestWithFallback(PI_ENDPOINT_VALIDATE_CHECK, parameters, headers, RequestMethod::POST);

	// If the response is empty, there was an error in the endpoint
	if (response.empty())
	{
		PIDebug("Response was empty. Endpoint error: " + Convert::LongToHexString(_endpoint.GetLastErrorCode()));
		return _endpoint.GetLastErrorCode();
	}

	return EvaluateResponse(response, responseObj);
}

HRESULT PrivacyIDEA::ValidateCheckCompletePasskeyRegistration(
	const std::string& transactionId,
	const std::string& serial,
	const std::wstring& username,
	const std::wstring& domain,
	FIDORegistrationResponse registrationResponse,
	const std::string& origin,
	PIResponse& piresponse)
{
	map<string, string> parameters = {
		{"user", Convert::ToString(username)},
		{"serial", serial},
		{"type", "passkey"},
		{"transaction_id", transactionId},
		{"credential_id", registrationResponse.credentialId},
		{"clientDataJSON", registrationResponse.clientDataJSON},
		{"attestationObject", registrationResponse.attestationObject},
		{"authenticatorAttachment", registrationResponse.authenticatorAttachment},
		{"rawId", registrationResponse.credentialId}
	};
	AppendRealm(domain, parameters);
	map<string, string> headers = { { "Origin", origin } };

	string response = SendRequestWithFallback(PI_ENDPOINT_VALIDATE_CHECK, parameters, headers, RequestMethod::POST);

	return EvaluateResponse(response, piresponse);
}

HRESULT PrivacyIDEA::ValidateInitialize(PIResponse& response, const std::string& type)
{
	PIDebug(__FUNCTION__);
	map<string, string> parameters = { { "type", type } };
	string r = SendRequestWithFallback(PI_ENDPOINT_VALIDATE_INITIALIZE, parameters, {}, RequestMethod::POST);
	return EvaluateResponse(r, response);
}

/*!

@return PI_OFFLINE_NO_OFFLINE_DATA, PI_OFFLINE_DATA_NO_OTPS_LEFT, S_OK, E_FAIL
*/
HRESULT PrivacyIDEA::OfflineCheck(const std::wstring& username, const std::wstring& otp, __out std::string& serialUsed)
{
	PIDebug(__FUNCTION__);
	string szUsername = Convert::ToString(username);

	HRESULT res = offlineHandler.VerifyOfflineOTP(otp, szUsername, serialUsed);
	PIDebug("Offline verification result: " + Convert::LongToHexString(res));
	return res;
}

HRESULT PrivacyIDEA::OfflineRefill(const std::wstring& username, const std::wstring& lastOTP, const std::string& serial)
{
	PIDebug(__FUNCTION__);
	string refilltoken;
	string szUsername = Convert::ToString(username);
	string szLastOTP = Convert::ToString(lastOTP);

	HRESULT hr = offlineHandler.GetRefillToken(szUsername, serial, refilltoken);
	if (hr != S_OK)
	{
		PIDebug("Failed to get parameters for offline refill!");
		return E_FAIL;
	}

	map<string, string> parameters = {
		{"pass", szLastOTP},
		{"refilltoken", refilltoken},
		{"serial", serial}
	};

	string response = SendRequestWithFallback(PI_ENDPOINT_OFFLINE_REFILL, parameters, map<string, string>(), RequestMethod::POST);

	if (response.empty())
	{
		PIDebug("Offline refill response was empty");
		return _endpoint.GetLastErrorCode();
	}

	OfflineData data;
	hr = _parser.ParseRefillResponse(response, szUsername, data);
	// Add the serial off the token used to be able to identify it when adding new data
	data.serial = serial;
	offlineHandler.AddOfflineData(data);
	return hr;
}

HRESULT PrivacyIDEA::OfflineRefillFIDO(const std::wstring& username, const std::string& serial)
{
	PIDebug(__FUNCTION__);
	string refilltoken;
	string szUsername = Convert::ToString(username);

	HRESULT hr = offlineHandler.GetRefillToken(szUsername, serial, refilltoken);
	if (hr != S_OK)
	{
		PIDebug("Failed to get parameters for offline refill!");
		return E_FAIL;
	}

	map<string, string> parameters = {
		{"refilltoken", refilltoken},
		{"serial", serial},
		{"pass", ""}
	};

	string response = SendRequestWithFallback(PI_ENDPOINT_OFFLINE_REFILL, parameters, map<string, string>(), RequestMethod::POST);

	if (response.empty())
	{
		PIDebug("Offline refill response was empty");
		return _endpoint.GetLastErrorCode();
	}

	if (!_parser.IsStillActiveOfflineToken(response))
	{
		PIDebug("Token " + serial + " is not marked for offline use anymore, its data is removed from this machine");
		offlineHandler.RemoveOfflineData(szUsername, serial);
	}
	else
	{
		refilltoken = _parser.GetRefilltoken(response);
		if (refilltoken.empty())
		{
			PIDebug("Refilltoken is empty");
			return E_FAIL;
		}
		if (!offlineHandler.UpdateRefilltoken(serial, refilltoken))
		{
			PIDebug("Failed to update refilltoken for serial " + serial);
			return E_FAIL;
		}
	}

	return hr;
}

bool PrivacyIDEA::StopPoll()
{
	PIDebug("Stopping poll thread...");
	_runPoll.store(false);
	return true;
}

void PrivacyIDEA::PollTransactionAsync(
	std::wstring username,
	std::wstring domain,
	std::wstring upn,
	std::string transactionId,
	std::function<void(const PIResponse&)> callback)
{
	_runPoll.store(true);
	std::thread t(&PrivacyIDEA::PollThread, this, username, domain, upn, transactionId, callback);
	t.detach();
}

bool PrivacyIDEA::PollTransaction(std::string transactionId)
{
	map<string, string> parameters = {
		{"transaction_id", transactionId }
	};

	string response = SendRequestWithFallback(PI_ENDPOINT_POLLTRANSACTION, parameters, map<string, string>(), RequestMethod::GET);
	PIDebug("Polltransaction response: " + response);
	return _parser.ParsePollTransaction(response);
}
