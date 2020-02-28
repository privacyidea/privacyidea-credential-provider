.. _configuration:

Configuration
=============

During installation of the privacyIDEA Credential Provider you already
configured all necessary settings, but it can be interesting to change
settings later. Like changing the available credential providers or changing
the verification of the authentication server certificate.

Registry Settings
-----------------

If you want to change the configuration after the installation, you can only do this by editing the registry keys.
You can use administrative templates to deploy the credential provider on many desktops in your network.

The configuration is located at
``Computer\HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-CP\``.


Connection Settings
~~~~~~~~~~~~~~~~~~~

These settings define the connection to the privacyIDEA server.
The connection is established via https by default, like indicated in the installer.

**hostname**

The hostname of the privacyIDEA Authentication Service. That usually is something
like  *yourserver.example.com* without any additional path information.

**path**

Optional. 
The path to the privacyIDEA Authentication Service if there is.
E.g. */test/path/pi*

NOTE: The entry */path/to/pi* is a placeholder. If it is read by the Credential Provider, it is treated as an empty entry.

**ssl_ignore_invalid_cn**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an invalid common name.

**ssl_ignore_unknown_ca**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an unknown CA.

**custom_port**

This entry is not there by default. You can add it to declare a custom port. The value has to be of type *REG_SZ* with the name *custom_port*.

NOTE: By default the port is the default https port, which is 443.

Login behaviour
~~~~~~~~~~~~~~~

Using these settings you can specify the behaviour of the privacyIDEA Credential Provider. The credential provider
can ask for the username, the password and the otp value in one step or in two steps.

**two_step_hide_otp**

Set to ``1`` if the privacyIDEA Credential Provider should ask for the user's OTP in a second step. In the first step the user will only be asked for the password.

**two_step_send_password**

Set to ``1`` if the privacyIDEA Credential Provider should send the user's password to the privacyIDEA Authentication Service.

**two_step_send_empty_password**

Set to ``1`` if the privacyIDEA Credential Provider should send an empty password to the privacyIDEA Authentication Service.

NOTE: If both **two_step_send_password** and **two_step_send_empty_password** are set to ``1``, the privacyIDEA Credential Provider will send an empty password to the privacyIDEA Authentication Service.
NOTE: Sending the windows or an empty password can be used to trigger token types like SMS or Email.

Recommended setup for remote desktop scenarios
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In scenarios where the privacyIDEA Credential Provider shall be used for RDP connections, it is recommended to install the privacyIDEA Credential Provider only on the RDP target together with the Filter.
It is also recommended to use the *two_step_hide_otp* setting to skip entering the windows password a second time.


Customization of the Look and Feel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also change the look and feel of the privacyIDEA Credential Provider.


**login_text**

Specify the text that is displayed underneath the credential logo and on the right side where available credentials are listed. 
The default is "privacyIDEA Login".

**otp_text**

Speficy the text that is displayed in the OTP input field. Usually this is "One-Time Password", but you can
change it to any other value you like.

**otp_hint_text**

Speficy the text that is displayed when prompted to enter the OTP in the second step.
The default is "Please enter your second factor!".

**otp_fail_text**

Specify a custom text that is shown when the OTP verification failed. The default is "Wrong One-Time Password!".
NOTE: An error on either the client or server side overwrites this message.

**hide_domainname**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide only the domain name when the desktop is locked.

**hide_fullname**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide the user and domain name when the desktop is locked.
Instead only the contents of the *login_text* settings will be displayed.

**v1_bitmap_path**

The complete path and filename of a bitmap image. This is a customized 
login image. The image must be a version 3 Windows BMP file with a resolution
of 128x128 pixels.

**no_default**

Add this registry entry and set it ``1`` to not have the privacyIDEA Credential Provider selected by default when logging in.

**offline_file**

Specify the **absolute** path to where the offline file should be saved. The default is C:\offlineFile.json.
NOTE: Either txt or json file type is recommended.

**offline_try_window**

Specify how many offline values shall be compared to the input at max. Default is 10. A value of 0 equals the default.



Realms
~~~~~~

Realms are implemented by mapping Windows domains to privacyIDEA realms. When a matching mapping exists, the &realm=... parameter
is added to the request. 

**default_realm**

Specify a default realm. If set, it is appended to every request that has no other matching mapping.


The mapping is done in the sub key ``realm-mapping`` (=> HKEY_LOCAL_MACHINE\SOFTWARE\Netknights GmbH\PrivacyIDEA-CP\realm-mapping).
Here you can specify the Windows domains as the names and the privacyIDEA realms as data of REG_SZ entries.


Log file
~~~~~~~~

**release_log**

Set to ``1`` if you want the privacyIDEA Credential Provider to write a logfile in the release version. The log only contains errors and is located at C:\\privacyIDEAReleaseLogFile.txt.

The log file of the debug version contains more detailed information and is located at C:\\privacyIDEADebugLogFile.txt

**log_sensitive**

In some cases it can be useful to log sensitive data (e.g. passwords) to find the cause of a problem. By default sensitive data is not logged. 
To log sensitive data aswell, create a new registry key of type *REG_SZ* with the name *log_sensitive* and a value of *1*. This can be deleted after creating a logfile.
NOTE: This only affects the *debug* versions of the privacyIDEA Credential Provider.
