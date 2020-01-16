
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

For more information on the privacyIDEA Credential Provider see
https://netknights.it/en/produkte/privacyidea-credential-provider/

Documentation
=============
The documentation can be found in ``/doc``.

Build
=====
The Solution is built using the platform tools v140 (VS 2015)

Dependencies
============
This project requires *json.hpp* from https://github.com/nlohmann/json, put it in ``/nlohmann/json.hpp``.
