/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2024 NetKnights GmbH
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

#pragma once
#include "FIDO2SignRequest.h"
#include "FIDO2SignResponse.h"
#include "OfflineData.h"
#include "FIDO2RegistrationRequest.h"
#include "FIDO2RegistrationResponse.h"
#include <string>
#include <fido.h>
#include <vector>
#include <optional>

constexpr auto fidoFlags = FIDO_DISABLE_U2F_FALLBACK | FIDO_DEBUG;

constexpr auto FIDO2DEVICE_ERR_TX = 0x88809089;

constexpr auto OFFLINE_CHALLENGE_SIZE = 64;

class FIDO2Device
{
public:
	static std::vector<FIDO2Device> GetDevices(bool log=true);

	FIDO2Device(const fido_dev_info_t* devinfo, bool log=true);
	FIDO2Device() = default;

	int Sign(const FIDO2SignRequest& signRequest, const std::string& origin, const std::string& pin, FIDO2SignResponse& signResponse) const;

	int SignAndVerifyAssertion(const std::vector<OfflineData>& offlineData, const std::string& origin, const std::string& pin, std::string& serialUsed) const;

	std::optional<FIDO2RegistrationResponse> Register(const FIDO2RegistrationRequest& registration, const std::string& pin);

	std::string GetPath() const { return _path; }
	std::string GetManufacturer() const { return _manufacturer; }
	std::string GetProduct() const { return _product; }
	bool HasPin() const noexcept { return _hasPin; }
	bool IsWinHello() const noexcept { return _isWinHello; }
	bool HasUV() const noexcept { return _hasUV; }

private:
	int GetDeviceInfo();

	std::string BuildAttestationObject(fido_cred_t* cred);

	std::string _path;
	std::string _manufacturer;
	std::string _product;
	bool _hasPin = false;
	bool _isWinHello = false;
	bool _hasUV = false;
	std::vector<int> _supportedAlgorithms;
	int _remainingResidentKeys = -1;
	bool _newPinRequired = false;
};
