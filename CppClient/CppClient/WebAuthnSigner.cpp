#include "WebAuthnSigner.h"
#include "Convert.h"
#include "Logger.h"
#include <webauthn.h>

HRESULT WebAuthnSigner::Sign(
	HWND hWnd,
	WebAuthnSignRequest request,
	WebAuthnSignResponse& response,
	const std::string& origin,
	const std::string& hashAlgorithm)
{
	// RP information
	WEBAUTHN_RP_ENTITY_INFORMATION rPInformation = {
		WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, // Structure version
		Convert::ToWString(request.rpId).c_str(),		// ID
		Convert::ToWString(request.rpId).c_str(),		// Friendly name
		nullptr,										// Icon
	};

	// Allow credential
	std::vector<WEBAUTHN_CREDENTIAL> vCredList;
	for (auto& allowCred : request.allowCredentials)
	{
		DWORD cbCredId = 0;
		PBYTE pbCredId = Convert::Base64ToPByte(allowCred.id, cbCredId);
		WEBAUTHN_CREDENTIAL credential = {
			WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
			cbCredId,
			pbCredId,
			WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY
		};
		vCredList.push_back(credential);
	}
#pragma warning(disable: 4838 4267)
	WEBAUTHN_CREDENTIALS credentialList = {
		vCredList.size(),
		vCredList.data()
	};
#pragma warning(default: 4838 4267)

	// Assertion options
	WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS webAuthNAssertionOptions = {
		WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,	// Structure version
		60000,															// Timeout in ms
		credentialList,													// Credential list
		{0, NULL},														// Extensions
		WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,							// Authenticator attachment
		WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,				// Require User Verification
		0,																// dwFlags
		NULL,															// optional pwszU2fAppId
		NULL,															// optional *pbU2fAppId
		nullptr,														// pCancellationId
		NULL,															// optional pAllowCredentialList, not needed because already provided
	};

	// Client data (challenge)
	DWORD cbCdata = 0;
	std::string cData = "{\"type\": \"webauthn.get\", \"challenge\": \"" + request.challenge + "\", \"origin\": \"" + origin + "\", \"crossOrigin\": false}";
	auto bytes = std::vector<BYTE>(cData.begin(), cData.end());
	std::string clientDataB64 = Convert::PByteToBase64URL(bytes.data(), bytes.size());
	WEBAUTHN_CLIENT_DATA webAuthNClientData = {
		WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,   // Structure version
		bytes.size(),							// cbClientDataJSON
		bytes.data(),							// pbClientDataJSON
		WEBAUTHN_HASH_ALGORITHM_SHA_256,		// Hash algorithm
	};

	PWEBAUTHN_ASSERTION pWebAuthNAssertion = nullptr;
	HRESULT hr = WebAuthNAuthenticatorGetAssertion(
		hWnd,
		rPInformation.pwszId,
		&webAuthNClientData,
		&webAuthNAssertionOptions,
		&pWebAuthNAssertion);

	if (SUCCEEDED(hr) && pWebAuthNAssertion != nullptr)
	{
		PIDebug("WebAuthNAuthenticatorGetAssertion succeeded.");
		std::string credentialId = Convert::PByteToBase64URL(pWebAuthNAssertion->Credential.pbId, pWebAuthNAssertion->Credential.cbId);
		std::string authenticatorData = Convert::PByteToBase64URL(pWebAuthNAssertion->pbAuthenticatorData, pWebAuthNAssertion->cbAuthenticatorData);
		std::string signatureData = Convert::PByteToBase64URL(pWebAuthNAssertion->pbSignature, pWebAuthNAssertion->cbSignature);
		// TODO userhandle, extensions
		response = WebAuthnSignResponse(credentialId, clientDataB64, authenticatorData, signatureData);
	}
	else
	{
		PIError(L"WebAuthNAuthenticatorGetAssertion failed " + std::to_wstring(hr) + L". Error name: " + WebAuthNGetErrorName(hr));
	}

	WebAuthNFreeAssertion(pWebAuthNAssertion);
	return hr;
}
