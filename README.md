The privacyIDEA Credential Provider adds multifactor authentication to the Windows Desktop or Server login.

The Credential Provider communicates with the privacyIDEA authentication system via REST API.

[privacyIDEA is an open source two factor authentication system](https://github.com/privacyidea/privacyidea)

### Features
* FIDO Authentication with Passkey/WebAuthn
    - Usernameless
    - Offline
    - With RDP
* Push Token with the [privacyIDEA Authenticator App](https://github.com/privacyidea/pi-authenticator)
* OTP Token like HOTP, TOTP, Email or SMS
* Configurable usage depending on scenario (Logon, Unlock with RDP or local)
* Fallback/recovery options
    - Excluded Account
    - Excluded Group
    - Fallback URL
* Configurable texts

### Test Version and Enterprise Support
If you just want to test the software, an MSI is available in the release section as well as a test subscription.

[Enterprise Support and an extended Subscription](https://netknights.it/en/produkte/privacyidea-credential-provider/) is provided by NetKnights, who also advance the development of this project and privacyIDEA.

### Documentation
The documentation can be found in ``/doc``, most notably the [configuration options](https://github.com/privacyidea/privacyidea-credential-provider/blob/master/doc/configuration.rst).

The complete documentation can be found at [readthedocs.io](https://privacyidea-credential-provider.readthedocs.io/en/latest/index.html).

### Dependencies
This project requires [json.hpp](https://github.com/nlohmann/json) in ``CppClient/nlohmann/json.hpp``.
It also requires [libfido2](https://developers.yubico.com/libfido2/Releases/) for Windows to be in the ``$SolutionDir$`` (or adjust the include settings).
Supports libfido2 with PCSC enabled. 

To build the installer, the VC143 merge modules are required to be in ``lib/merge``.
