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

#pragma once
#include "FIDOSignRequest.h"
#include "FIDOSignResponse.h"
#include "OfflineData.h"
#include "FIDORegistrationRequest.h"
#include "FIDORegistrationResponse.h"
#include <string>
#include <fido.h>
#include <vector>
#include <optional>

constexpr auto fidoFlags = FIDO_DISABLE_U2F_FALLBACK | FIDO_DEBUG;

constexpr auto FIDO_DEVICE_ERR_TX = 0x88809089;

constexpr auto OFFLINE_CHALLENGE_SIZE = 64;

class FIDODevice
{
public:
	static std::vector<FIDODevice> GetDevices(bool filterWindowsHello = true, bool log = true);

	FIDODevice(const fido_dev_info_t* devinfo, bool log = true);
	FIDODevice() = default;

	int Sign(
		const FIDOSignRequest& signRequest,
		const std::string& origin,
		const std::string& pin,
		FIDOSignResponse& signResponse) const;

	int SignAndVerifyAssertion(
		const std::vector<OfflineData>& offlineData,
		const std::string& origin,
		const std::string& pin,
		std::string& serialUsed) const;

	std::optional<FIDORegistrationResponse> Register(
		const FIDORegistrationRequest& registration,
		const std::string& pin);

	std::string GetPath() const { return _path; }
	std::string GetManufacturer() const { return _manufacturer; }
	std::string GetProduct() const { return _product; }
	bool HasPin() const noexcept { return _hasPin; }
	bool IsWinHello() const noexcept { return _isWinHello; }
	bool HasUV() const noexcept { return _hasUV; }

	static std::string GenerateRandomAsBase64URL(long size);
	std::string ToString() const;

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
	long _remainingResidentKeys = -1;
	bool _newPinRequired = false;
};
