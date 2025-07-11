#pragma once
#include <string>

class FIDO2RegistrationResponse
{
public:
    FIDO2RegistrationResponse() = default;

    FIDO2RegistrationResponse(
        std::string authenticatorData,
        std::string signature,
        std::string credentialId,
        std::string largeBlobKey,
        std::string clientDataHash,
        std::string aaguid,
        std::string publicKey,
        std::string x5c,
        std::string attestationObject,
		std::string clientDataJSON,
		std::string authenticatorAttachment,
		std::string userHandle)
        : authenticatorData(std::move(authenticatorData)),
        signature(std::move(signature)),
        credentialId(std::move(credentialId)),
        largeBlobKey(std::move(largeBlobKey)),
        clientDataHash(std::move(clientDataHash)),
        aaguid(std::move(aaguid)),
        publicKey(std::move(publicKey)),
        x5c(std::move(x5c)),
        attestationObject(std::move(attestationObject)),
		clientDataJSON(std::move(clientDataJSON)),
		authenticatorAttachment(std::move(authenticatorAttachment)),
		userHandle(std::move(userHandle))
    {}

    std::string authenticatorData;
    std::string signature;
    std::string credentialId;
    std::string largeBlobKey;
    std::string clientDataHash;
    std::string aaguid;
    std::string publicKey;
    std::string x5c;
    std::string attestationObject;
    std::string clientDataJSON;
    std::string authenticatorAttachment;
	std::string userHandle;
};