.. _configuration:

Configuration
=============

During installation of the privacyIDEA Credential Provider you already
configured all necessary settings, but it can be interesting to change
settings later. Like changing the available credential providers or changing
the verification of the authentication server certificate.

To change these settings, go to the Windows control panel and "change" the
privacyIDEA Credential Provider. You will run through the same configuration
dialogs like during :ref:`installation`.

Registry Settings
-----------------

You can configure the privacyIDEA Credential Provider directly by modifying
the corresponding registry keys. You can use administrative templates
to deploy the credential provider on many desktops in your network.

The configuration is located at
``Computer\HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-CP\``.


Connection Settings
~~~~~~~~~~~~~~~~~~~

These settings define the connection to the privacyIDEA server.

**server_url**

The base URL of the privacyIDEA Authentication Service. Usually this is
*https://yourserver/privacyidea* without any additional path information.

**ssl_ignore_invalid_cn**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an invalid common name.

**ssl_ignore_unknown_ca**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an unknown CA.

Login behaviour
~~~~~~~~~~~~~~~

Using these settings you can specify the behaviour of the privacyIDEA Credential Provider. The credential provider
can ask for the username, the password and the otp value in one step or in two steps.

**two_step_hide_otp**

Set to ``1`` if the privacyIDEA Credential Provider should ask for the user's OTP in a second step. In the first step the user will only be asked for the password.

**two_step_send_password**

Set to ``1`` if the privacyIDEA Credential Provider should send the user's password to the privacyIDEA Authentication Service.


Customization of the Look and Feel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also change the look and feel of the privacyIDEA Credential Provider.


**login_text**

Specify the text, that is displayed underneath the credential provider logo.

**otp_text**

Speficy the text, that is displayed in the OTP input field. Usually this is "One-Time Password", but you can
change it to any other value you like.

**hide_username**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide the username when the desktop is locked.
Instead only the contents of the *login_text* settings will be displayed.

**v1_bitmap_path**

The complete path and filename of a bitmap image. This is a customized 
login image. The image must be a version 3 Windows BMP file with a resolution
of 128x128 pixels.

