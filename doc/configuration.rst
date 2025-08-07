.. _configuration:

Configuration
=============

During installation of the privacyIDEA Credential Provider you already
configured all necessary settings, but it can be interesting to change
settings later. Like changing the available credential providers or changing
the verification of the authentication server certificate.

-----------------
Registry Settings
-----------------

If you want to change the configuration after the installation, you can only do this by editing the registry keys.
You can use administrative templates to deploy the credential provider on many desktops in your network.

The configuration is located at
``Computer\HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-CP\``.


.. note:: If an entry is missing, you can just create a new entry of type REG_SZ with the corresponding name.

-------------------
Connection Settings
-------------------

These settings define the connection to the privacyIDEA server.
The connection is established via https by default, like indicated in the installer.

**hostname**

The hostname of the privacyIDEA Authentication Service. That usually is something
like  *yourserver.example.com* without any additional path information.

**path**

The path to the privacyIDEA Authentication Service if there is.
E.g. */test/path/pi*

.. note:: The entry */path/to/pi* is a placeholder. If it is read by the Credential Provider, it is treated as an empty entry.

**custom_port**

This entry is not there by default. You can add it to declare a custom port. The value has to be of type *REG_SZ* with the name *custom_port*.

.. note:: By default the port is the default https port, which is 443.

**ssl_ignore_invalid_cn**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an invalid common name.

**ssl_ignore_unknown_ca**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an unknown CA.

**resolve_timeout, connect_timeout, send_timeout, receive_timeout**

With these entries you can specify the timeout (in ms) for the corresponding phase. This might be interesting if the offline feature
is used. The default timeouts are infinite / 60s / 30s / 30s.

-----------------
Recovery settings
-----------------

**fallback_hostname, fallback_path, fallback_port**

These settings allow to specify a fallback URL, which, when at least the hostname is set, will be used in case the primary hostname is not available.
Once that happens, the fallback setting will be used for the rest of the authentication session.

**excluded_account**

Specify an account that should be excluded from 2FA. The format is required to be ``domain\username`` or ``computername\username``.

**excluded_group**

Specify a group whose members are excluded from 2FA. Can be a local, global or nested group. 
.. note:: global groups require **excluded_account_netbios_address** to be set.

**excluded_account_netbios_address**

The NetBIOS address of the computer to query for global groups. You can get a list of candidates for example by running ``netdom query dc``, which will give you a list of Domain Controllers.

----------------------------------
Login Behaviour and User Interface
----------------------------------

Using these settings you can specify the behaviour and UI of the privacyIDEA Credential Provider.
By default, the Credential Provider will prompt for username -> MFA -> password. Optionally you can set it to username+password, then MFA.

**v1_bitmap_path**

The complete path and filename of a bitmap image. This is a customized login image. 
The image must be a version 3 Windows BMP file with a resolution of 128x128 pixels.

**username_password**

Set to ``1`` if the privacyIDEA Credential Provider will prompt for username and password in the first step.

**two_step_send_password**

Set to ``1`` if the privacyIDEA Credential Provider should send the user's password to privacyIDEA, potentially triggering tokens. This can be useful with the policy ``otppin=userstore``.
If this is enabled, the Credential Provider will automatically prompt for username and password in the first step.

**two_step_send_empty_password**

Set to ``1`` if the privacyIDEA Credential Provider should send an empty password to the privacyIDEA Authentication Service.
Enabling this will **not** cause the Credential Provider to automatically prompt for username and password in the first step.
.. note:: If both **two_step_send_password** and **two_step_send_empty_password** are set to ``1``, the privacyIDEA Credential Provider will send an empty password to privacyIDEA.

**send_upn**

Set to ``1`` to send the UPN instead of username and domain to privacyIDEA.The determination if the username input is a UPN is currently very basic and will assume an UPN if there is an @ and no \ contained in the input.
If the input is not an UPN, the usual realm settings are applied.

**hide_domainname**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide only the domain name when the desktop is locked.

**hide_fullname**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide the user and domain name when the desktop is locked.
Instead only the contents of the *login_text* settings will be displayed.

**no_default**

Add this registry entry and set it ``1`` to **not** have the privacyIDEA Credential Provider selected by default when logging in. 
This will only have an effect if there are other Credential Providers available.

**show_domain_hint**

Set this to ``1`` to show the domain that is currently used to log in.

**prefill_username**

Set this to ``1`` to have the username field prefilled with the user that last logged on.

**enable_reset**

Set this to ``1`` to have a clickable text shown at the bottom which will reset the login.

**otp_fail_return_to_first_step**

Set to ``1`` to return to the first step after entering a wrong OTP. Default is ``0``, so after entering a wrong OTP, you are prompted for the OTP again.

**hide_first_step_response_error**

Set to ``1`` to hide the fail message, like "wrong OTP PIN", when using **two_step_send_empty_password** or **two_step_send_password** and no token has been triggered. 
Instead, the default prompt will be shown.

**header_accept_language**

Set this to an valid accept language header like "en-GB" or "de-DE". Alternatively, if left empty or the value is "system", the system language will be used.
This header will be used in requests to privacyIDEA and the messages privacyIDEA returns will be localized in that language if a translation is available and there is no policy active that
would set the corresponding message to a configured value.

-----------------
Customizing Texts
-----------------

Starting with version 3.7.0 of the Credential Provider, you can customize all texts that are used. You can also modify or add translations.
The translation files are installed to ``C:\ProgramData\Netknights GmbH\PrivacyIDEA Credential Provider\locales``. To edit these files, you need to change their permissions, or use "Take Ownership".
In previous versions of the Credential Provider, you could specify custom texts for some things. These settings have been superceded by the translation and customization system.
Here is a list of the old configuration options and their corresponding ID in the translation files:
* otp_link_text = 13
* reset_link_text = 8
* otp_fail_text = 7
* otp_text = 6
* login_text = 17
* webauthn_link_text = 12
* webauthn_pin_hint = 14

**language**

You can overwrite the language of the Credential Provider by setting this to a valid language code, like "en" or "de". A translation file for that language has to exist in the locales folder.

------------------------------------------
Filter and Scenario Specific Configuration
------------------------------------------

The Filter is an additional component of a credential provider. It can be used to filter out other credential providers (e.g. the system ones).
By default, if our filter is enabled, it will filter every other credential provider so that the privacyIDEA CP is the only one usable.

**enable_filter**

Set this to ``1`` to enable the filter of the privacyIDEA Credential Provider. If this is disabled, the privacyIDEA CP will just be listed *in addition*
to the other existing CPs.

**filter_whitelist**

Add entries to this REG_MULTI_SZ to spare other CPs from being filtered. The entry has to be the CLSID of a CP.
One way to check the CLSID of a CP is to look at
``HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers``

There are different *credential provider usage scenarios* ("cpus"). The available
scenarios are *logon*, *unlock* and *credui*.

It is possible to configure both the Credential Provider and the Filter for each of the scenarios.
This way the administrator can define a different behaviour if a users either logs in or
unlocks his desktop.

For the configurations in this section to take effect, the *enable_filter* setting has to be enabled in v3.2 or higher.

The behaviour in each scenario can be configured via the corresponding registry
entry named **cpus_logon**, **cpus_unlock** and **cpus_credui**.

These entries expect a *REG_SZ*, that consist of a digit 0, 1, 2, 3 and a
character "e" or "d".

* 0: relevant for *remote* (RDP) and *local* operation
* 1: relevant for *remote* operation
* 2: relevant for *local* operation
* 3: the privacyIDEA Credential Provider will *not* be shown in remote and local operation.

The characters stand for:

* "e": Only the privacyIDEA Credential Provider is available. All other
  credential providers are not available.
* "d": The privacyIDEA Credential Provider will be available *in addition* to all other Credential Providers on the machine.

E.g. This would result in:

* ``cpus_logon = 0e``: Only the privacyIDEA Credential Provider is available for
  Logon via remote and locally.

* ``cpus_unlock = 1d``: Remotely the locked destop can be unlocked with all
  available Credential Providers, including the privacyIDEA Credential Provider.

* ``cpus_unlock = 2e``: Locally unlocking the desktop is only possible with the
  privacyIDEA Credential Provider.

* ``cpus_credui = 3d``: For credui scenarios, the privacyIDEA Credential Provider
  is disabled and will not be shown, no matter if remotely or locally. Only the other
  credential providers are available.
  (Note: "3e" does not exist, because there would be no credential provider available)

If there is no entry for a scenario, the default is assumed:
The privacyIDEA Credential Provider will be available and the Filter will be active, if installed.

.. note:: Starting with Windows 10, CPUS_UNLOCK is not triggered by default anymore when unlocking the workstation. Instead, unlocking the workstation is considered CPUS_LOGON. If you need to differentiate the two scenarios, disabling fast user switching in the group policy editor restores the previous behavior. An example of how to do this can be found here: https://support.waters.com/KB_Inf/Empower_Breeze/WKB47366_How_To_Enable_Disable_Fast_User_Switching_In_Windows_10

.. note:: To use the Credential Provider in CredUI Scenarios on Priviliged Access Workstations with Admin Accounts see https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4

----------------------------------------------
Recommended setup for remote desktop scenarios
----------------------------------------------

In scenarios where the privacyIDEA Credential Provider is to be used for RDP connections, it is recommended to install the privacyIDEA Credential Provider only on the RDP target.
The Filter has to be enabled for RDP scenarios, otherwise Windows will use the System Credential Provider automatically!

----
FIDO
----

The Credential Provider supports FIDO Authentication without EntraID. Starting with version 3.7.0 it also supports FIDO in RDP scenarios, by using Windows Hello in these cases.
Currently, a passwordless login is not possible, as the Credential Provider Interface requires to provide a username, domain and password for the login. We are working on providing a solution for this.
To use passkey and therefore have a usernameless login, just press the link at the bottom to initiate the login with a passkey. 
This will cover the username and MFA step in one and the Credential Provider will prompt for the password in the last step.
Because a password (knowledge factor) is still required here, you can disable the *user_verification*, meaning the prompt for the PIN of the security key, for the Credential Provider, 
by creating a policy with ``webauthn_user_verification_requirement=discouraged`` in privacyIDEA. It is advised to use this policy only for the credential provider, e.g. by making a condition on the user agent or IP.
In other cases where passwordless login is possible, using this policy would result in a login with only one factor, the ownership of the security key, but no knowledge factor (PIN/Password).

To use WebAuthn token, it is required to configure **two_step_send_empty_password** or **two_step_send_password** to trigger a challenge! WebAuthn token are not usernameless.
By default, Passkey token can *not* be triggered like WebAuthn token. You can set the policy ``passkey_trigger_by_pin=true`` in privacyIDEA, to have Passkeys behave like WebAuthn token and the Credential Provider is able to handle that aswell.

.. note:: CURRENTLY SUPPORTS ONLY A SINGLE CONNECTED FIDO2 DEVICE. IF MORE THAN ONE DEVICE IS CONNECTED, THE "FIRST ENUMERATED" WILL BE USED, WHICH IS A NON-DETERMINISTIC SELECTION!

.. note:: AFTER YOU ARE PROMPTED TO TOUCH YOUR SECURITY KEY, IT IS NOT POSSIBLE TO CANCEL THE OPERATION. EVENTHOUGH THERE IS A CANCEL BUTTON, THE CONTROL IS TRANSFERED TO THE DEVICE UNTIL THE OPERATION IS COMPLETED OR TIMED OUT!**

.. note:: WINDOWS HELLO IS NOT SUPPORTED FOR LOCAL LOGINS BECAUSE THE UI CAN NOT BE RENDERED IN LOGON/UNLOCK SCENARIOS. TO USE FIDO IN RDP SCENARIOS, ONLY WINDOWS HELLO WILL BE USED, BECAUSE IT HANDLES THE TUNNELING OF THE FIDO DATA TO THE LOCAL DEVICE.**

**disable_passkey**

Set to ``1`` to disable the option to log in with a passkey, that is offered in the first step.

**webauthn_preferred**

Set to ``1`` to continue directly with webauthn mode after receiving a webauthn challenge. By default, the second step is OTP.

**webauthn_offline_no_pin**

Set this to ``1`` to not be prompted for the security key PIN when doing offline authentication with WebAuthn or Passkey. Online authentications remain controlled by privacyIDEA.

-------------
Offline Token
-------------

HOTP and FIDO (WebAuthn and Passkey) token can be configured to be usable without a connection to privacyIDEA. On the detail page of the token in privacyIDEA, select Application => Offline at the bottom.
Now the token has to be used online once with the Credential Provider, to get the configured amount of OTPs in advance.
The use of HOTP offline is not recommended any more, because the token will become unusable for online authentication or any other machine other than the one that has the offline values.
FIDO token do not have this restriction and can be used for online and offline authentications simultaneously. The offline data of a FIDO token can also be on multiple devices.

The following settings can be useful with offline token:

**offline_file**

Specify the **absolute** path to where the offline file should be saved. The default is ``C:\offlineFile.json``.

.. note:: Either txt or json file type is recommended. The data that is saved is in json format.

**offline_try_window**

Specify how many offline values shall be compared to the input at max. Default is 10. A value of 0 equals the default.

**offline_threshold**

Specify the number of remaining OTP values below which a refill should be attempted. Refilling is done online and therefore requires a connection to the server.
If the machine is really offline and refill is attempted, this will cause a timeout and thus slow down the login. 
By default, refill is attempted after every successful offline authentication. However, if 100 offline values are available, it is not neccessary to try refilling after every authentication.

**offline_show_info**

Set this to ``1`` to show information about available offline token for the current user. This will trigger as soon as the input from the username field matches a user for which offline token are available.

------
Realms
------

Realms are implemented by mapping Windows domains to privacyIDEA realms. When a matching mapping exists, the &realm=... parameter
is added to the request.

**default_realm**

Specify a default realm. If set, it is appended to every request that has no other matching mapping.

The mapping is done in the sub key ``realm-mapping`` (=> HKEY_LOCAL_MACHINE\\SOFTWARE\\Netknights GmbH\\PrivacyIDEA-CP\\realm-mapping).
Here you can specify the Windows domains as the names and the privacyIDEA realms as data of REG_SZ entries.

-------
Logging
-------

**debug_log**

Set to ``1`` if you want the privacyIDEA Credential Provider to write a detailed log file, which is helpful when reporting bugs.
The log file is located at C:\\PICredentialProviderLog.txt.
If this setting is disabled, actual errors are still written to the log file.

**log_sensitive**

In some cases it can be useful to log sensitive data (e.g. passwords) to find the cause of a problem. 
By default, sensitive data is not logged. Instead it is only logged if the password contains a value.
To log sensitive data aswell, create a new registry key of type *REG_SZ* with the name *log_sensitive* and a value of *1*. This can be deleted after creating a log file.
