#include <iostream>
#include "PrivacyIDEA.h"
#include "PIWebAuthn.h"
#include "Convert.h"
#include "Logger.h"
#include "WebAuthnSigner.h"

using namespace std;

int main()
{
	string origin = "test.office.netknights.it";
	PIConfig conf;
	conf.hostname = L"pi02.office.netknights.it";
	conf.ignoreInvalidCN = true;
	conf.ignoreUnknownCA = true;
	conf.defaultRealm = L"defrealm";
	Logger::Get().logDebug = true;
	PrivacyIDEA privacyidea(conf);
	PIResponse response;
	std::wstring username = L"games";
	HWND hWnd = GetForegroundWindow();
	
	bool online = true;
	if (online)
	{
		auto hr = privacyidea.ValidateCheck(username, L"", L"12", response);

		PIWebAuthn webAuthn;
		WebAuthnSigner signer;
		WebAuthnSignRequest signRequest = response.challenges[0].webAuthnSignRequest;
		WebAuthnSignResponse signResponse;
		hr = signer.Sign(hWnd, signRequest, signResponse, origin, "SHA-256");
		PIResponse secondResponse;

		if (SUCCEEDED(hr))
		{
			hr = privacyidea.ValidateCheckWebAuthn(username, L"", signResponse, origin, secondResponse, response.transactionId);

			if (SUCCEEDED(hr))
			{
				PIDebug("WebAuthn validation successful");
			}
			else
			{
				PIDebug("WebAuthn validation failed");
			}
		}
		return hr;
	}

	HRESULT hr = S_OK;
	PIWebAuthn webAuthn;
	string credentialId = "PvJOtRemNhgORKyY1JYqM1-ZVihMgqCdeSX_aYoZF2Q-3-ADzZSxIF4_LBEzzvpp2H32m4NbIw0m9U9sWlbhbg";
	// Create a signrequest
	WebAuthnSignRequest signRequest;
	AllowCredential allowCredential;
	allowCredential.id = credentialId;
	allowCredential.transports = { "internal", "ble", "usb", "nfc" };
	
	signRequest.allowCredentials = { allowCredential };
	signRequest.rpId = L"office.netknights.it";
	signRequest.timeout = 60000;
	signRequest.userVerification = "preferred";
	signRequest.challenge = "5eFtBwwMWHnV4VWApw9Xp5qLFmADhcUWPgKsdijy6ds";
	
	// Create a StoredCredential
	StoredWebAuthnCredential storedCredential;
	storedCredential.cosePublicKey = "a5010203262001215820c7782b25c86b343931aa976265359b7c1090379936398d9ea55a4d7eb56160be225820c21041f2f73a9cd3ddfc0ef98961df398209df6d84010cd4018a563673305e98";
	storedCredential.credentialId = credentialId;
	
	// Create a signresponse
	WebAuthnSignResponse signResponse;
	/*
	authenticatorData: YgXNXddv4CjdMv50VAhTaPANtrGt2a6niL1j3nAUulsFAAAARQ
clientData: eyJ0eXBlIjogIndlYmF1dGhuLmdldCIsICJjaGFsbGVuZ2UiOiAiNWVGdEJ3d01XSG5WNFZXQXB3OVhwNXFMRm1BRGhjVVdQZ0tzZGlqeTZkcyIsICJvcmlnaW4iOiAidGVzdC5vZmZpY2UubmV0a25pZ2h0cy5pdCIsICJjcm9zc09yaWdpbiI6IGZhbHNlfQ
credentialId: PvJOtRemNhgORKyY1JYqM1-ZVihMgqCdeSX_aYoZF2Q-3-ADzZSxIF4_LBEzzvpp2H32m4NbIw0m9U9sWlbhbg
signature: MEYCIQD3cC7zGoMsMFyThoZ20ipEGyMwzddnURnQK-OvyvMCCAIhAM5AZ8twRfy8LiEitZZ0ZmvhqTjKSIzCemRongIJ9idd
	*/
	signResponse.authenticatordata = "YgXNXddv4CjdMv50VAhTaPANtrGt2a6niL1j3nAUulsFAAAARQ";
	signResponse.clientdata = "eyJ0eXBlIjogIndlYmF1dGhuLmdldCIsICJjaGFsbGVuZ2UiOiAiNWVGdEJ3d01XSG5WNFZXQXB3OVhwNXFMRm1BRGhjVVdQZ0tzZGlqeTZkcyIsICJvcmlnaW4iOiAidGVzdC5vZmZpY2UubmV0a25pZ2h0cy5pdCIsICJjcm9zc09yaWdpbiI6IGZhbHNlfQ";
	signResponse.credentialid = "PvJOtRemNhgORKyY1JYqM1-ZVihMgqCdeSX_aYoZF2Q-3-ADzZSxIF4_LBEzzvpp2H32m4NbIw0m9U9sWlbhbg";
	signResponse.signaturedata = "MEYCIQD3cC7zGoMsMFyThoZ20ipEGyMwzddnURnQK-OvyvMCCAIhAM5AZ8twRfy8LiEitZZ0ZmvhqTjKSIzCemRongIJ9idd";
	
	/*hr = webAuthn.Sign(hWnd, signRequest, signResponse, origin, "SHA-256");
	if (hr != 0)
	{
		PIDebug("WebAuthn sign failed");
		return hr;
	}*/

	webAuthn.VerifyWebAuthnSignResponse(signResponse, signRequest, storedCredential, origin);
}
