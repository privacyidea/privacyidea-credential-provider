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
#include <cbor.h>
#include <fido/es256.h>
#include <memory>
#include <algorithm>
#include <fido/credman.h>
#include "Convert.h"
#include "FIDODevice.h"
#include "Logger.h"
#include "PrivacyIDEA.h"
#include "FIDOException.h"
#include "FIDORegistrationResponse.h"

struct FidoDevDeleter
{
	void operator()(fido_dev_t* dev) const
	{
		if (dev)
		{
			fido_dev_close(dev);
			fido_dev_free(&dev);
		}
	}
};
using unique_fido_dev_t = std::unique_ptr<fido_dev_t, FidoDevDeleter>;

struct FidoCredDeleter
{
	void operator()(fido_cred_t* cred) const
	{
		if (cred)
		{
			fido_cred_free(&cred);
		}
	}
};
using unique_fido_cred_t = std::unique_ptr<fido_cred_t, FidoCredDeleter>;

struct FidoAssertDeleter
{
	void operator()(fido_assert_t* a) const
	{
		if (a) fido_assert_free(&a);
	}
};
using unique_fido_assert_t = std::unique_ptr<fido_assert_t, FidoAssertDeleter>;

namespace
{
	constexpr auto COSE_PUB_KEY_ALG = 3;
	constexpr auto COSE_PUB_KEY_X = -2;
	constexpr auto COSE_PUB_KEY_Y = -3;
	constexpr auto COSE_PUB_KEY_E = -2;
	constexpr auto COSE_PUB_KEY_N = -1;

	static int EcKeyFromCBOR(
		const std::string& cborPubKey,
		EC_KEY** ecKey,
		int* algorithm)
	{
		int res = FIDO_OK;
		std::vector<unsigned char> pubKeyBytes;
		if (cborPubKey.length() % 2 == 0)
		{
			// hex encoded
			pubKeyBytes = Convert::HexToBytes(cborPubKey);
		}
		else
		{
			pubKeyBytes = Convert::Base64URLDecode(cborPubKey);
		}

		struct cbor_load_result result;
		cbor_item_t* map = cbor_load(pubKeyBytes.data(), pubKeyBytes.size(), &result);

		if (map == NULL)
		{
			PIError("Failed to parse CBOR public key");
			return FIDO_ERR_INVALID_ARGUMENT;
		}
		if (!cbor_isa_map(map))
		{
			PIError("CBOR public key is not a map");
			cbor_decref(&map);
			return FIDO_ERR_INVALID_ARGUMENT;
		}

		size_t size = cbor_map_size(map);
		cbor_pair* pairs = cbor_map_handle(map);
		//cbor_map
		// Find the algorithm
		int alg = 0;
		for (int i = 0; i < size; i++)
		{
			if (cbor_isa_uint(pairs[i].key) && cbor_get_uint8(pairs[i].key) == COSE_PUB_KEY_ALG)
			{
				if (cbor_isa_negint(pairs[i].value))
				{
					alg = -1 - cbor_get_int(pairs[i].value);
				}
			}
		}

		// Depending on the algorithm, find the values to build the public key	
		if (alg == COSE_ES256)
		{
			*algorithm = alg;
			std::vector<uint8_t> x, y;
			for (int i = 0; i < size; i++)
			{
				if (cbor_isa_negint(pairs[i].key))
				{
					int key = -1 - cbor_get_int(pairs[i].key);
					if (key == COSE_PUB_KEY_X)
					{
						if (cbor_isa_bytestring(pairs[i].value))
						{
							x = std::vector<uint8_t>(cbor_bytestring_handle(pairs[i].value), cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value));
						}
					}
					else if (key == COSE_PUB_KEY_Y)
					{
						if (cbor_isa_bytestring(pairs[i].value))
						{
							y = std::vector<uint8_t>(cbor_bytestring_handle(pairs[i].value), cbor_bytestring_handle(pairs[i].value) + cbor_bytestring_length(pairs[i].value));
						}
					}
				}
			}

			if (x.size() != 32)
			{
				PIError("COSE_PUB_KEY_X has the wrong size. Expected 32, actual: " + std::to_string(x.size()));
				cbor_decref(&map);
				return FIDO_ERR_INVALID_ARGUMENT;
			}
			if (y.size() != 32)
			{
				PIError("COSE_PUB_KEY_Y has the wrong size. Expected 32, actual: " + std::to_string(y.size()));
				cbor_decref(&map);
				return FIDO_ERR_INVALID_ARGUMENT;
			}

			// secp256r1 is called prime256v1 in OpenSSL (RFC 5480, Section 2.1.1.1)
			*ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			BIGNUM* bnx = BN_new();
			BN_bin2bn(x.data(), x.size(), bnx);
			BIGNUM* bny = BN_new();
			BN_bin2bn(y.data(), y.size(), bny);
			EC_KEY_set_public_key_affine_coordinates(*ecKey, bnx, bny);
			BN_free(bnx);
			BN_free(bny);
		}
		else
		{
			// TODO implement other COSE algorithms if supported by privacyIDEA
			PIError("Unimplemented alg: " + std::to_string(alg));
			res = FIDO_ERR_INVALID_ARGUMENT;
		}

		cbor_decref(&map);
		return res;
	}

	static unique_fido_dev_t OpenFidoDevice(const std::string& devicePath, int& outError)
	{
		outError = FIDO_OK;
		if (devicePath.empty())
		{
			PIError("No device path provided");
			outError = FIDO_ERR_INVALID_ARGUMENT;
			return nullptr;
		}

		unique_fido_dev_t dev(fido_dev_new());
		if (!dev)
		{
			PIError("fido_dev_new failed.");
			outError = FIDO_ERR_INTERNAL;
			return nullptr;
		}

		int res = fido_dev_open(dev.get(), devicePath.c_str());
		if (res != FIDO_OK)
		{
			PIError("fido_dev_open: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
			outError = FIDO_ERR_INTERNAL;
			return nullptr;
		}

		return dev;
	}

	static int GetAssert(
		const FIDOSignRequest& signRequest,
		const std::string& origin,
		const std::string& pin,
		const std::string& devicePath,
		fido_assert_t** assert,
		std::vector<unsigned char>& clientDataOut)
	{
		int res = FIDO_OK;
		auto dev = OpenFidoDevice(devicePath, res);

		// Create assertion
		if ((*assert = fido_assert_new()) == NULL)
		{
			PIError("fido_assert_new failed.");
			fido_dev_close(dev.get());
			return FIDO_ERR_INTERNAL;
		}

		// Allow Creds
		for (auto& allowCred : signRequest.allowCredentials)
		{
			auto cred = Convert::Base64URLDecode(allowCred.id);
			res = fido_assert_allow_cred(*assert, cred.data(), cred.size());
			if (res != FIDO_OK)
			{
				PIDebug("fido_assert_allow_cred: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
			}
		}

		// Passkey challenges are not bound to a specific credential, so allowCredentials are empty. The encoding of the challenge is different in this case.
		bool isPasskeyChallenge = signRequest.allowCredentials.empty();
		std::string challenge = signRequest.challenge;
		if (signRequest.type == "passkey" || isPasskeyChallenge)
		{
			std::vector<unsigned char> bytes(signRequest.challenge.begin(), signRequest.challenge.end());
			challenge = Convert::Base64URLEncode(bytes.data(), bytes.size());
		}
		std::string cData = "{\"type\": \"webauthn.get\", \"challenge\": \"" + challenge + "\", \"origin\": \"" + origin + "\", \"crossOrigin\": false}";
		clientDataOut = std::vector<unsigned char>(cData.begin(), cData.end());
		res = fido_assert_set_clientdata(*assert, clientDataOut.data(), clientDataOut.size());
		if (res != FIDO_OK)
		{
			PIDebug("fido_assert_set_clientdata: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		}

		// RP
		res = fido_assert_set_rp(*assert, signRequest.rpId.c_str());
		if (res != FIDO_OK)
		{
			PIDebug("fido_assert_set_rp: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		}

		// Extensions TODO
		/*res = fido_assert_set_extensions(*assert, NULL);
		if (res != FIDO_OK)
		{
			PIDebug("fido_assert_set_extensions: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		}*/

		// User verification
		bool hasUV = fido_dev_has_uv(dev.get());
		PIDebug("Device has user verification: " + std::to_string(hasUV) + " and request is: " + signRequest.userVerification);

		if (hasUV && signRequest.userVerification == "discouraged")
		{
			res = fido_assert_set_uv(*assert, FIDO_OPT_FALSE);
			if (res != FIDO_OK)
			{
				PIDebug("fido_assert_set_uv: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
			}
			else
			{
				PIDebug("User verification set to 'discouraged'");
			}
		}

		// Get assert and close
		res = fido_dev_get_assert(dev.get(), *assert, pin.empty() ? NULL : pin.c_str());
		return res;
	}

	inline bool CborAddItemToMap(
		cbor_item_t* map,
		const std::string& key,
		cbor_item_t* (*valueFactory)(const void*, size_t),
		const void* valueData,
		size_t valueSize)
	{
		if (!map || !cbor_isa_map(map))
		{
			return false;
		}

		cbor_item_t* cbor_key = cbor_build_string(key.c_str());
		if (!cbor_key)
		{
			return false;
		}

		cbor_item_t* cbor_value = valueFactory(valueData, valueSize);
		if (!cbor_value)
		{
			cbor_decref(&cbor_key);
			return false;
		}

		struct cbor_pair pair {};
		pair.key = cbor_key;
		pair.value = cbor_value;

		if (!cbor_map_add(map, pair))
		{
			cbor_decref(&cbor_key);
			cbor_decref(&cbor_value);
			return false;
		}

		return true;
	}

	inline bool CborAddBytesToMap(cbor_item_t* map, const std::string& key, const std::vector<unsigned char>& value)
	{
		return CborAddItemToMap(
			map,
			key,
			[](const void* data, size_t size) { return cbor_build_bytestring(static_cast<const unsigned char*>(data), size); },
			value.data(),
			value.size()
		);
	}

	inline bool CborAddStringToMap(cbor_item_t* map, const std::string& key, const std::string& value)
	{
		return CborAddItemToMap(
			map,
			key,
			[](const void* data, size_t size) { return cbor_build_string(static_cast<const char*>(data)); },
			value.c_str(),
			value.size()
		);
	}

	inline std::vector<unsigned char> CborMapToBytes(cbor_item_t* map)
	{
		unsigned char* buffer = nullptr;
		size_t buffer_size = 0;
		if (!map)
		{
			return {};
		}
		buffer_size = cbor_serialize_alloc(map, &buffer, &buffer_size);
		if (buffer_size == 0 || buffer == nullptr)
		{
			return {};
		}
		std::vector<unsigned char> result(buffer, buffer + buffer_size);
		free(buffer); // libcbor uses malloc/free
		return result;
	}

	inline bool CborAddMapToMap(cbor_item_t* destMap, const std::string& key, cbor_item_t* srcMap)
	{
		if (!destMap || !srcMap || !cbor_isa_map(destMap) || !cbor_isa_map(srcMap))
		{
			return false;
		}

		cbor_item_t* srcMapCopy = cbor_copy(srcMap);
		if (!srcMapCopy)
		{
			return false;
		}

		cbor_item_t* cbor_key = cbor_build_string(key.c_str());
		if (!cbor_key)
		{
			cbor_decref(&srcMapCopy);
			return false;
		}

		struct cbor_pair pair {};
		pair.key = cbor_key;
		pair.value = srcMapCopy;

		if (!cbor_map_add(destMap, pair))
		{
			cbor_decref(&cbor_key);
			cbor_decref(&srcMapCopy);
			return false;
		}

		return true;
	}

	inline cbor_item_t* CborMapFromBytes(const std::vector<unsigned char>& data)
	{
		if (data.empty())
		{
			return nullptr;
		}
		struct cbor_load_result result;
		cbor_item_t* item = cbor_load(data.data(), data.size(), &result);
		if (!item || !cbor_isa_map(item))
		{
			if (item) cbor_decref(&item);
			return nullptr;
		}
		return item;
	}
}

std::vector<FIDODevice> FIDODevice::GetDevices(bool filterWindowsHello, bool log)
{
	if (log)
	{
		PIDebug("Searching for connected FIDO devices, filterWindowsHello=" + std::to_string(filterWindowsHello));
	}
	fido_init(fidoFlags);
	std::vector<FIDODevice> ret;
	size_t ndevs;
	int res = FIDO_OK;
	fido_dev_info_t* deviceList = nullptr;
	if ((deviceList = fido_dev_info_new(64)) == NULL)
	{
		PIError("fido_dev_info_new returned NULL");
		return ret;
	}

	if ((res = fido_dev_info_manifest(deviceList, 64, &ndevs)) != FIDO_OK)
	{
		std::string fidoStrerr = fido_strerr(res);
		PIError("fido_dev_info_manifest: " + fidoStrerr + " " + std::to_string(res));
		return ret;
	}

	for (size_t i = 0; i < ndevs; i++)
	{
		const fido_dev_info_t* di = fido_dev_info_ptr(deviceList, i);
		FIDODevice dev(di);
		if (dev.IsWinHello() && filterWindowsHello)
		{
			continue;
		}
		ret.push_back(dev);
	}
	if (log)
	{
		PIDebug("Found " + std::to_string(ret.size()) + " FIDO device(s)");
	}
	return ret;
}

FIDODevice::FIDODevice(const fido_dev_info_t* devinfo, bool log)
{
	unique_fido_dev_t dev(fido_dev_new_with_info(devinfo));
	if (dev == NULL)
	{
		PIError("Unable to allocate for fido_dev_t");
		return;
	}

	int res = fido_dev_open_with_info(dev.get());
	if (res != FIDO_OK)
	{
		PIError("fido_dev_open_with_info: " + std::string(fido_strerr(res)) + " " + std::to_string(res));
	}
	else
	{
		_path = fido_dev_info_path(devinfo);
		_manufacturer = fido_dev_info_manufacturer_string(devinfo);
		_product = fido_dev_info_product_string(devinfo);
		_hasPin = fido_dev_has_pin(dev.get());
		_isWinHello = fido_dev_is_winhello(dev.get());
		_hasUV = fido_dev_has_uv(dev.get());
		if (log)
			PIDebug("New FIDO device: " + ToString() + " hasPin: " + std::to_string(_hasPin) + " isWinHello: " + std::to_string(_isWinHello));
	}
	GetDeviceInfo();
}

std::string FIDODevice::ToString() const
{
	return "[" + _manufacturer + "][" + _product + "][" + _path + "]";
}

std::vector<std::string> FIDODevice::GetRpIds(std::string pin) const
{
	PIDebug(__FUNCTION__);
	std::vector<std::string> ret;
	int res = FIDO_OK;
	auto dev = OpenFidoDevice(_path, res);

	fido_credman_rp_t* rp = fido_credman_rp_new();
	if (!rp)
	{
		PIError("fido_credman_rp_new failed.");
		fido_dev_close(dev.get());
		return ret; // throw exception
	}

	res = fido_credman_get_dev_rp(dev.get(), rp, pin.empty() ? NULL : pin.c_str());
	if (res != FIDO_OK)
	{
		PIError("fido_credman_get_dev_rp: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		fido_credman_rp_free(&rp);
		fido_dev_close(dev.get());
		return ret; // throw exception
	}

	size_t rp_count = fido_credman_rp_count(rp);
	for (size_t i = 0; i < rp_count; ++i)
	{
		const char* rp_id = fido_credman_rp_id(rp, i);
		if (rp_id)
		{
			ret.push_back(rp_id);
		}
	}

	fido_credman_rp_free(&rp);
	return ret;
}

std::vector<std::string> FIDODevice::GetUsersForRpId(std::string pin, std::string rpId) const
{
	PIDebug(__FUNCTION__);
	std::vector<std::string> ret;

	int res = FIDO_OK;
	auto dev = OpenFidoDevice(_path, res);
	if (res != FIDO_OK)
	{
		PIError("Failed to open FIDO device: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		return ret; // throw exception
	}

	fido_credman_rk_t* rk = fido_credman_rk_new();
	if (!rk)
	{
		PIError("fido_credman_rk_new failed.");
		return ret; // throw exception
	}

	res = fido_credman_get_dev_rk(dev.get(), rpId.c_str(), rk, pin.empty() ? NULL : pin.c_str());
	if (res != FIDO_OK)
	{
		PIError("fido_credman_get_dev_rk: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		fido_credman_rk_free(&rk);
		return ret; // throw exception
	}

	size_t rk_count = fido_credman_rk_count(rk);
	for (size_t i = 0; i < rk_count; ++i)
	{
		auto cred = fido_credman_rk(rk, i);
		ret.push_back(fido_cred_user_name(cred));
	}

	fido_credman_rk_free(&rk);
	return ret;
}

int FIDODevice::Sign(
	const FIDOSignRequest& signRequest,
	const std::string& origin,
	const std::string& pin,
	FIDOSignResponse& signResponse) const
{
	fido_assert_t* assert = nullptr;
	std::vector<unsigned char> vecClientData;
	int res = GetAssert(signRequest, origin, pin, _path, &assert, vecClientData);

	if (res != FIDO_OK)
	{
		PIDebug("fido_dev_get_assert: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
	}

	if (res == FIDO_OK)
	{
		signResponse.clientdata = Convert::Base64URLEncode(vecClientData);

		auto pbId = fido_assert_id_ptr(assert, 0);
		auto cbId = fido_assert_id_len(assert, 0);
		signResponse.credentialid = Convert::Base64URLEncode(pbId, cbId);

		auto pbAuthData = fido_assert_authdata_raw_ptr(assert, 0);
		auto cbAuthData = fido_assert_authdata_raw_len(assert, 0);
		signResponse.authenticatordata = Convert::Base64URLEncode(pbAuthData, cbAuthData);

		auto pbSig = fido_assert_sig_ptr(assert, 0);
		auto cbSig = fido_assert_sig_len(assert, 0);
		signResponse.signaturedata = Convert::Base64URLEncode(pbSig, cbSig);

		auto pbUserHandle = fido_assert_user_id_ptr(assert, 0);
		auto cbUserHandle = fido_assert_user_id_len(assert, 0);
		signResponse.userHandle = Convert::Base64URLEncode(pbUserHandle, cbUserHandle);
	}

	fido_assert_free(&assert);

	return res;
}

std::string FIDODevice::GenerateRandomAsBase64URL(long size)
{
	PUCHAR buf = new UCHAR[size];
	auto status = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, buf, size, 0);
	if (status != 0)
	{
		PIError("BCryptGenRandom failed with error: " + std::to_string(status));
		delete[] buf;
		return "";
	}

	std::string ret = Convert::Base64URLEncode(buf, size);
	delete[] buf;
	return ret;
}

int FIDODevice::SignAndVerifyAssertion(
	const std::vector<OfflineData>& offlineData,
	const std::string& origin,
	const std::string& pin,
	std::string& serialUsed) const
{
	// Make a signRequest from the offlineData
	FIDOSignRequest signRequest;
	signRequest.rpId = offlineData.front().rpId;
	signRequest.challenge = GenerateRandomAsBase64URL(OFFLINE_CHALLENGE_SIZE);
	for (auto& item : offlineData)
	{
		if (item.rpId != signRequest.rpId)
		{
			PIError("Offline data for ID " + item.credId + " has different rpId. Expected: " + signRequest.rpId + ", actual: " + item.rpId);
			PIError("The data will not be used for offline authentication");
		}
		else
		{
			AllowCredential cred;
			cred.id = item.credId;
			signRequest.allowCredentials.push_back(cred);
		}
	}

	fido_assert_t* assert = nullptr;
	std::vector<unsigned char> cDataBytes;
	int res = GetAssert(signRequest, origin, pin, _path, &assert, cDataBytes);

	EC_KEY* ecKey = nullptr;
	es256_pk_t* pk = es256_pk_new();
	int algorithm;

	if (res == FIDO_OK)
	{
		// Find the credential which signed the assert and use it's public key to verify the signature
		auto pbId = fido_assert_id_ptr(assert, 0);
		auto cbId = fido_assert_id_len(assert, 0);
		auto idUsed = Convert::Base64URLEncode(pbId, cbId);
		std::string pubKey;
		for (auto& item : offlineData)
		{
			if (item.credId == idUsed)
			{
				pubKey = item.pubKey;
				serialUsed = item.serial;
				break;
			}
		}

		if (pubKey.empty())
		{
			PIError("No public key provided");
			return FIDO_ERR_INVALID_ARGUMENT;
		}

		res = EcKeyFromCBOR(pubKey, &ecKey, &algorithm);
		if (ecKey == nullptr)
		{
			PIError("Failed to create EC_KEY");
			return FIDO_ERR_INTERNAL;
		}

		// TODO other algorithms if privacyidea supports them
		if (algorithm != COSE_ES256)
		{
			PIError("Unsupported algorithm: " + std::to_string(algorithm));
			return FIDO_ERR_UNSUPPORTED_OPTION;
		}

		res = es256_pk_from_EC_KEY(pk, ecKey);
		if (res == FIDO_OK)
		{
			res = fido_assert_verify(assert, 0, algorithm, pk);
			if (res == FIDO_OK)
			{
				PIDebug("Assertion verified successfully!");
			}
			else
			{
				PIError("fido_assert_verify: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
			}
		}
		else
		{
			PIError("es256_pk_from_EC_KEY: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		}
	}
	else
	{
		PIError("fido_dev_get_assert: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
	}

	if (pk)
	{
		es256_pk_free(&pk);
	}
	if (ecKey)
	{
		EC_KEY_free(ecKey);
	}
	if (assert)
	{
		fido_assert_free(&assert);
	}

	return res;
}

std::optional<FIDORegistrationResponse> FIDODevice::Register(
	const FIDORegistrationRequest& registration,
	const std::string& pin)
{
	if (_path.empty())
	{
		PIError("No device path provided");
		throw FIDOException("No device path available to register credential."); // Throw here
	}

	unique_fido_dev_t dev(fido_dev_new());
	if (!dev)
	{
		PIError("fido_dev_new failed.");
		throw FIDOException(FIDO_ERR_INTERNAL, "Failed to initialize FIDO device context.");
	}

	int res = fido_dev_open(dev.get(), _path.c_str());
	if (res != FIDO_OK)
	{
		PIError("fido_dev_open: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to open FIDO device.");
	}

	unique_fido_cred_t cred(fido_cred_new());
	if (!cred)
	{
		PIError("fido_cred_new failed.");
		throw FIDOException(FIDO_ERR_INTERNAL, "Failed to initialize FIDO credential context.");
	}

	int type = COSE_ES256;
	if (!_isWinHello)
	{
		if (_supportedAlgorithms.empty())
		{
			PIError("No supported algorithms found");
			throw FIDOException("No supported algorithms found in device configuration.");
		}

		// Find the first supported algorithm from the registration request
		bool algoFound = false;
		for (const auto& item : registration.pubKeyCredParams)
		{
			if (std::find(_supportedAlgorithms.begin(), _supportedAlgorithms.end(), item.second) != _supportedAlgorithms.end())
			{
				type = item.second;
				algoFound = true;
				break;
			}
		}

		if (!algoFound)
		{
			PIError("None of the requested algorithms are supported by the device.");
			throw FIDOException("Requested public key credential parameters not supported by FIDO device.");
		}
	}
	else
	{
		PIDebug("Device is Windows Hello, using ES256 as default algorithm.");
	}

	// Cred Type
	if ((res = fido_cred_set_type(cred.get(), type)) != FIDO_OK)
	{
		PIError("fido_cred_set_type: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set credential type.");
	}
	// RP
	if ((res = fido_cred_set_rp(cred.get(), registration.rpId.c_str(), registration.rpName.c_str())) != FIDO_OK)
	{
		PIError("fido_cred_set_rp: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set relying party.");
	}

	// Client Data
	// Client data: Passkey challenge has different encoding, so encode it here again
	std::string challenge = registration.challenge;
	if (registration.type == "passkey")
	{
		std::vector<unsigned char> bytes(registration.challenge.begin(), registration.challenge.end());
		challenge = Convert::Base64URLEncode(bytes.data(), bytes.size());
	}
	std::string clientData = "{ \"type\":\"webauthn.create\", \"challenge\" : \"" + challenge + "\", \"origin\" : \""
		+ registration.rpId + "\", \"crossOrigin\" : false }";
	auto clientDataBytes = std::vector<unsigned char>(clientData.begin(), clientData.end());
	res = fido_cred_set_clientdata(cred.get(), clientDataBytes.data(), clientDataBytes.size());
	if (res != FIDO_OK)
	{
		PIDebug("fido_cred_set_clientdata: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set client data for credential creation.");
	}

	// FMT
	std::string fmt = "packed";
	res = fido_cred_set_fmt(cred.get(), fmt.c_str());
	if (res != FIDO_OK)
	{
		PIError("fido_cred_set_fmt: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set credential format.");
	}

	// User ID
	auto userId = Convert::Base64URLDecode(registration.userId);
	if ((res = fido_cred_set_user(cred.get(),
		userId.data(),
		userId.size(),
		registration.userName.c_str(),
		registration.userDisplayName.c_str(),
		NULL)) != FIDO_OK)
	{
		PIError("fido_cred_set_user: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set user information.");
	}

	// Resident Key (RK)
	fido_opt_t rk = registration.residentKey ? FIDO_OPT_TRUE : FIDO_OPT_FALSE;
	if ((res = fido_cred_set_rk(cred.get(), rk)) != FIDO_OK)
	{
		PIError("fido_cred_set_rk: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set resident key option.");
	}

	// UV
	fido_opt_t uv = registration.userVerification ? FIDO_OPT_TRUE : FIDO_OPT_FALSE;
	if ((res = fido_cred_set_uv(cred.get(), uv)) != FIDO_OK)
	{
		PIError("fido_cred_set_uv: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set user verification option.");
	}

	// Timeout
	if ((res = fido_dev_set_timeout(dev.get(), 120000)) != FIDO_OK)
	{
		PIError("fido_dev_set_timeout: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to set device timeout.");
	}

	// TODO fido_cred_exclude, fido_cred_empty_exclude_list
	// TODO credprot
	// TODO extensions

	// Create Credential
	if ((res = fido_dev_make_cred(dev.get(), cred.get(), pin.c_str())) != FIDO_OK)
	{
		fido_dev_cancel(dev.get());
		PIError("fido_dev_make_cred: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		throw FIDOException(res, "Failed to create credential on FIDO device.");
	}

	// Extract data from the created credential
	FIDORegistrationResponse response;

	response.credentialId = Convert::Base64URLEncode(fido_cred_id_ptr(cred.get()), fido_cred_id_len(cred.get()));
	PIDebug("Credential ID: " + response.credentialId);
	response.clientDataJSON = Convert::Base64Encode(clientDataBytes);
	PIDebug("Client Data: " + response.clientDataJSON);
	response.authenticatorAttachment = "cross-platform";

	/*
	response.largeBlobKey = Convert::Base64URLEncode(fido_cred_largeblob_key_ptr(cred.get()), fido_cred_largeblob_key_len(cred.get()));
	PIDebug("Large Blob Key: " + response.largeBlobKey);
	response.clientDataHash = Convert::Base64URLEncode(fido_cred_clientdata_hash_ptr(cred.get()), fido_cred_clientdata_hash_len(cred.get()));
	PIDebug("Client Data Hash: " + response.clientDataHash);
	response.aaguid = Convert::Base64URLEncode(fido_cred_aaguid_ptr(cred.get()), fido_cred_aaguid_len(cred.get()));
	PIDebug("AAGUID: " + response.aaguid);
	response.publicKey = Convert::Base64URLEncode(fido_cred_pubkey_ptr(cred.get()), fido_cred_pubkey_len(cred.get()));
	PIDebug("Public Key: " + response.publicKey);
	response.x5c = Convert::Base64URLEncode(fido_cred_x5c_ptr(cred.get()), fido_cred_x5c_len(cred.get()));
	PIDebug("x5c: " + response.x5c);
	response.attestationObject = Convert::Base64URLEncode(fido_cred_attstmt_ptr(cred.get()), fido_cred_attstmt_len(cred.get()));
	PIDebug("Attestation Statement: " + response.attestationObject);
	response.authenticatorData = Convert::Base64URLEncode(fido_cred_authdata_raw_ptr(cred.get()), fido_cred_authdata_raw_len(cred.get()));
	PIDebug("Authenticator Data: " + response.authenticatorData);
	response.signature = Convert::Base64URLEncode(fido_cred_sig_ptr(cred.get()), fido_cred_sig_len(cred.get()));
	PIDebug("Signature: " + response.signature);
	*/
	auto attestationObject = BuildAttestationObject(cred.get());
	if (attestationObject.empty())
	{
		throw FIDOException("Unable to create attestation statement!");
	}
	response.attestationObject = attestationObject;
	return response;
}

int FIDODevice::GetDeviceInfo()
{
	if (_path.empty())
	{
		PIError("No device path provided");
		return FIDO_ERR_INVALID_ARGUMENT;
	}

	int res = FIDO_OK;
	unique_fido_dev_t dev(fido_dev_new());
	if (dev == NULL)
	{
		PIError("fido_dev_new failed.");
		return FIDO_ERR_INTERNAL;
	}

	res = fido_dev_open(dev.get(), _path.c_str());
	if (res != FIDO_OK)
	{
		PIError("fido_dev_open: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		return FIDO_ERR_INTERNAL;
	}

	// Get info
	fido_cbor_info_t* info = fido_cbor_info_new();
	if (info == NULL)
	{
		PIError("Unable to allocate memory for fido_cbor_info_t!");
		res = FIDO_ERR_INTERNAL;
	}
	// This call may block
	res = fido_dev_get_cbor_info(dev.get(), info);
	if (res != FIDO_OK)
	{
		PIError("fido_dev_get_cbor_info: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		res = FIDO_ERR_INTERNAL;
	}

	if (res == FIDO_OK)
	{
		// Algorithms
		size_t nalg = fido_cbor_info_algorithm_count(info);
		for (size_t i = 0; i < nalg; i++)
		{
			auto alg = fido_cbor_info_algorithm_cose(info, i);
			_supportedAlgorithms.push_back(alg);
		}
		// Remaining Resident Keys
		auto remainingResidentKeys = fido_cbor_info_rk_remaining(info);
		if (remainingResidentKeys == -1)
		{
			//PIDebug("Authenticator can not report remaining resident keys");
		}
		else
		{
			_remainingResidentKeys = remainingResidentKeys;
		}
		// New PIN required
		_newPinRequired = fido_cbor_info_new_pin_required(info);

	}

	fido_cbor_info_free(&info);
	return 0;
}

std::string FIDODevice::BuildAttestationObject(fido_cred_t* cred)
{
	cbor_item_t* map = cbor_new_indefinite_map();
	if (!map)
	{
		PIError("Failed to allocate CBOR map for attestation object");
		return {};
	}

	// Add "fmt"
	if (!CborAddStringToMap(map, "fmt", "packed"))
	{
		PIError("Failed to add 'fmt' to attestation object CBOR map");
		cbor_decref(&map);
		return {};
	}

	// AuthData
	auto pAuthData = fido_cred_authdata_raw_ptr(cred);
	size_t authDataLen = fido_cred_authdata_raw_len(cred);
	if (!pAuthData || authDataLen == 0)
	{
		PIError("Invalid or empty authData in credential");
		cbor_decref(&map);
		return {};
	}
	std::vector<unsigned char> authData(pAuthData, pAuthData + authDataLen);
	if (!CborAddBytesToMap(map, "authData", authData))
	{
		PIError("Failed to add 'authData' to attestation object CBOR map");
		cbor_decref(&map);
		return {};
	}
	/*
	cbor_item_t* emptyMap = cbor_new_definite_map(0);
	add_cbor_map_to_cbor_map(map, "attStmt", emptyMap);
	*/

	// AttStmt
	auto pAttStmt = fido_cred_attstmt_ptr(cred);
	size_t attStmtLen = fido_cred_attstmt_len(cred);
	if (!pAttStmt || attStmtLen == 0)
	{
		PIError("Invalid or empty attStmt in credential");
		cbor_decref(&map);
		return {};
	}
	std::vector<unsigned char> attStmt(pAttStmt, pAttStmt + attStmtLen);
	// attStmt is a cbor map already, merge with root map
	cbor_item_t* attStmtMap = CborMapFromBytes(attStmt);
	if (!CborAddMapToMap(map, "attStmt", attStmtMap))
	{
		PIError("Failed to add 'authData' to attestation object CBOR map");
		cbor_decref(&map);
		cbor_decref(&attStmtMap);
		return {};
	}

	// Serialize and return
	auto mapBytes = CborMapToBytes(map);
	cbor_decref(&map);
	if (mapBytes.empty())
	{
		PIError("Failed to serialize attestation object CBOR map");
		return {};
	}
	return Convert::Base64URLEncode(mapBytes);
}
