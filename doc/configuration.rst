.. _configuration:

Configuration
=============

During installation of the privacyIDEA Credential Provider you already
configured all necessary settings. But it can be interesting, to change
settings later. Like changing the available credential providers or changing
the verification of the authentication server certificate.

To change these settings, go to the Windows control panel and "change" the
privacyIDEA Credential Provider. You will run through the same configuration
dialogs like during :ref:`installation`.

Registry Settings
-----------------

You can configure the privacyIDEA Credential Provider directly by modifying
the corresponding registry keys. You can use adminsitrative templates
 to deploy the credential provider on many desktops in your network.

The configuration is located at
``Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Last Squirrel IT\PrivacyIDEA-CP\``.

**login_test**

Specify the text, that is displayed underneath the credential provider logo.

**server_url**

The base URL of the privacyIDEA Authentication Service. Usually this is
*https://yourserver/* without any additional path information.

**ssl_verify_hostname**

Set to ``1`` if the privacyIDEA Credential Provider should check, if the
hostname in the certificate matches the hostname of the service.

**ssl_verify_signature**

Set to ``1`` if the privacyIDEA Credential Provider should check, if the
certificate has a valid signature of a trusted certificate authority.
