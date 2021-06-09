
About the privacyIDEA Credential Provider
=========================================

This is the privacyIDEA Credential Provider, which adds a second
factor of authentication at Windows Desktop or Server login.
Authentication is performed against the privacyIDEA Authentication System.

The Credential Provider communicates with the privacyIDEA authentication
system via a REST API.

privacyIDEA is an open source two factor authentication system. 

https://github.com/privacyidea/privacyidea

https://privacyidea.org

Test Version
============

If you just want to test the software, an MSI is available in the release section as well as a test subscription.

For Enterprise Support or an extended Subscription please check https://netknights.it/en/produkte/privacyidea-credential-provider/

Documentation
=============
The documentation can be found in ``/doc``.

Build
=====
The Solution is built using the platform tools v142 (VS 2019)

Dependencies
============
This project requires *json.hpp* from https://github.com/nlohmann/json, put it in ``CppClientCore/nlohmann/json.hpp``.
To build the installer, the VC142 merge modules are required to be in ``lib/merge``.