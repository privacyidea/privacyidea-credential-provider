#pragma once
#include <string>
#include <windows.h>
#include "WebAuthnSignRequest.h"
#include "WebAuthnSignResponse.h"

class WebAuthnSigner
{
public:
	/// <summary>
	/// Try to get an assertion from the authenticator using the Windows WebAuthn API.
	/// </summary>
	/// <param name="hWnd">Window handle</param>
	/// <param name="request">WebAuthnSignRequest</param>
	/// <param name="response">WebAuthnSignResponse if successful</param>
	/// <param name="origin">Origin</param>
	/// <param name="hashAlgorithm">SHA-256, SHA-384 or SHA-512. If the value is something else, SHA-256 will be used as default.</param>
	/// <returns>HRESULT from the WebAuthNAuthenticatorGetAssertion operation</returns>
	HRESULT Sign(
		HWND hWnd, 
		WebAuthnSignRequest request,
		WebAuthnSignResponse& response,
		const std::string& origin,
		const std::string& hashAlgorithm = "SHA-256");
};

