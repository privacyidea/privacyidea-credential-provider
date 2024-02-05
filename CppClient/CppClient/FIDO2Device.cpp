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
#include "Convert.h"
#include "FIDO2Device.h"
#include "Logger.h"
#include "PrivacyIDEA.h"
#include <cbor.h>
#include <fido/es256.h>
#include <iostream>

std::vector<FIDO2Device> FIDO2Device::GetDevices()
{
	PIDebug("Searching for connected FIDO2 devices");
	PIDebug("Filtering Windows Hello: " + std::to_string(filterWinHello));
	fido_init(fidoFlags);
	std::vector<FIDO2Device> ret;
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
		FIDO2Device dev(di);
		if (!(dev.IsWinHello() && filterWinHello))
		{
			ret.push_back(dev);
		}
	}

	return ret;
}

FIDO2Device::FIDO2Device(const fido_dev_info_t* devinfo)
{
	fido_dev_t* dev = fido_dev_new_with_info(devinfo);
	if (dev == NULL)
	{
		PIError("Unable to allocate for fido_dev_t");
		return;
	}

	int res = fido_dev_open_with_info(dev);
	if (res != FIDO_OK)
	{
		PIError("fido_dev_open_with_info: " + std::string(fido_strerr(res)) + " " + std::to_string(res));
	}

	_path = fido_dev_info_path(devinfo);
	_manufacturer = fido_dev_info_manufacturer_string(devinfo);
	_product = fido_dev_info_product_string(devinfo);
	_hasPin = fido_dev_has_pin(dev);
	_isWinHello = fido_dev_is_winhello(dev);
	_hasUV = fido_dev_has_uv(dev);
	PIDebug("New FIDO2 device: " + _manufacturer + " " + _product + " " + _path + " hasPin: " + std::to_string(_hasPin) + " isWinHello: " + std::to_string(_isWinHello));

	fido_dev_close(dev);
}

int GetAssert(
	const WebAuthnSignRequest& signRequest, 
	const std::string& origin,
	const std::string& pin,
	const std::string& devicePath, 
	fido_assert_t** assert, 
	std::vector<unsigned char>& clientDataOut)
{
	if (devicePath.empty())
	{
		PIError("No device path provided");
		return FIDO_ERR_INVALID_ARGUMENT;
	}

	// Create assertion
	if ((*assert = fido_assert_new()) == NULL)
	{
		PIError("fido_assert_new failed.");
		return FIDO_ERR_INTERNAL;
	}

	int res = FIDO_OK;

	// Allow Creds
	for (auto allowCred : signRequest.allowCredentials)
	{
		auto cred = Convert::Base64URLDecode(allowCred.id);
		res = fido_assert_allow_cred(*assert, cred.data(), cred.size());
		if (res != FIDO_OK)
		{
			PIDebug("fido_assert_allow_cred: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		}
	}

	// Client data
	std::string cData = "{\"type\": \"webauthn.get\", \"challenge\": \"" + signRequest.challenge + "\", \"origin\": \"" + origin + "\", \"crossOrigin\": false}";
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

	// EXT TODO
	res = fido_assert_set_extensions(*assert, NULL);
	if (res != FIDO_OK)
	{
		PIDebug("fido_assert_set_extensions: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
	}

	// TODO userhandle?

	// GET ASSERT
	fido_dev_t* dev = fido_dev_new();
	if (dev == NULL)
	{
		PIError("fido_dev_new failed.");
		return FIDO_ERR_INTERNAL;
	}

	fido_dev_open(dev, devicePath.c_str());
	res = fido_dev_get_assert(dev, *assert, pin.empty() ? NULL : pin.c_str());
	fido_dev_close(dev);
	/*
		WebAuthnSignResponse signResponse;
		signResponse.clientdata = Convert::Base64URLEncode(clientData);

		auto pID = fido_assert_id_ptr(*assert, 0);
		auto pIDlen = fido_assert_id_len(*assert, 0);
		signResponse.credentialid = Convert::Base64URLEncode(pID, pIDlen);

		auto adataraw = fido_assert_authdata_raw_ptr(*assert, 0);
		auto adatarawlen = fido_assert_authdata_raw_len(*assert, 0);
		auto adatarawenc = Convert::Base64URLEncode(adataraw, adatarawlen);
		signResponse.authenticatordata = adatarawenc;
		auto sig = fido_assert_sig_ptr(*assert, 0);
		auto siglen = fido_assert_sig_len(*assert, 0);
		signResponse.signaturedata = Convert::Base64URLEncode(sig, siglen);




		std::string pubkey = "a5010203262001215820ddcf9da43b0e38804a347860db7d4ef5ca906185e01a94dafa81b104ed19d9d2225820edf66881d7d36177bc1f7bc3b7a7d74660fa412f9e14d9e4cacc375b42cfea94";
		auto pubKeyBytes = Convert::HexToBytes(pubkey);
		void* pk = pubKeyBytes.data();
		int algorithm = COSE_ES256;
		res = fido_assert_verify(*assert, 0, algorithm, pk);
		if (res != FIDO_OK)
		{
			PIError("infunc fido_assert_verify: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
		}
		*/
	return res;
}

int FIDO2Device::Sign(
	const WebAuthnSignRequest& signRequest, 
	const std::string& origin,
	const std::string& pin, 
	WebAuthnSignResponse& signResponse) const
{
	fido_assert_t* assert = nullptr;
	std::vector<unsigned char> cDataBytes;
	int res = GetAssert(signRequest, origin, pin, _path, &assert, cDataBytes);

	if (res != FIDO_OK)
	{
		PIDebug("fido_dev_get_assert: " + std::string(fido_strerr(res)) + " code: " + std::to_string(res));
	}
	else
	{
		signResponse.clientdata = Convert::Base64URLEncode(cDataBytes);

		auto pID = fido_assert_id_ptr(assert, 0);
		auto pIDlen = fido_assert_id_len(assert, 0);
		signResponse.credentialid = Convert::Base64URLEncode(pID, pIDlen);

		auto adataraw = fido_assert_authdata_raw_ptr(assert, 0);
		auto adatarawlen = fido_assert_authdata_raw_len(assert, 0);
		auto adatarawenc = Convert::Base64URLEncode(adataraw, adatarawlen);
		signResponse.authenticatordata = adatarawenc;
		auto sig = fido_assert_sig_ptr(assert, 0);
		auto siglen = fido_assert_sig_len(assert, 0);
		signResponse.signaturedata = Convert::Base64URLEncode(sig, siglen);
	}

	if (assert)
	{
		fido_assert_free(&assert);
	}

	return res;
}

constexpr auto COSE_PUB_KEY_ALG = 3;
constexpr auto COSE_PUB_KEY_X = -2;
constexpr auto COSE_PUB_KEY_Y = -3;
constexpr auto COSE_PUB_KEY_E = -2;
constexpr auto COSE_PUB_KEY_N = -1;

int MakeEC_KEY(
	const std::string& cborPubKey, 
	EC_KEY** ecKey, 
	int* algorithm)
{
	int res = FIDO_OK;
	auto pubKeyBytes = Convert::HexToBytes(cborPubKey);
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

std::string GenerateRandomAsBase64URL(long size)
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

int FIDO2Device::SignAndVerifyAssertion(
	const std::vector<OfflineData>& offlineData, 
	const std::string& origin,
	const std::string& pin,
	std::string& serialUsed) const
{
	// Make a signRequest from the offlineData
	WebAuthnSignRequest signRequest;
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

		res = MakeEC_KEY(pubKey, &ecKey, &algorithm);
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
