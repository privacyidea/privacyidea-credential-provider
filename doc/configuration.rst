.. _configuration:

Configuration
=============

During the installation of the privacyIDEA Credential Provider, you already configured all necessary settings, but you may want to change them later. For example, you might want to change the available credential providers or the verification of the authentication server certificate.

-----------------
Registry Settings
-----------------

If you want to change the configuration after the installation, you must edit the registry keys. You can also use administrative templates to deploy the credential provider on many desktops in your network.

The configuration is located at
``Computer\HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-CP\``.

.. note:: If an entry is missing, you can just create a new entry of type REG_SZ with the corresponding name.

-------------------
Connection Settings
-------------------

These settings define the connection to the privacyIDEA server. The connection is established via HTTPS by default, as indicated in the installer.

**hostname**

The hostname of the privacyIDEA Authentication Service. This is usually something like *yourserver.example.com* without any additional path information.

**path**

The path to the privacyIDEA Authentication Service, if applicable.
E.g., */test/path/pi*

.. note:: The entry */path/to/pi* is a placeholder. If it is read by the Credential Provider, it is treated as an empty entry.

**custom_port**

This entry is not there by default. You can add it to declare a custom port. The value must be of type *REG_SZ* with the name *custom_port*.

.. note:: By default, the port is the default HTTPS port, which is 443.

**ssl_ignore_invalid_cn**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an invalid common name.

**ssl_ignore_unknown_ca**

Set to ``1`` if the privacyIDEA Credential Provider should ignore SSL errors originating from an unknown CA.

**resolve_timeout, connect_timeout, send_timeout, receive_timeout**

With these entries, you can specify the timeout (in milliseconds) for the corresponding phase. This is particularly useful if the offline feature is used. The default timeouts are infinite / 60s / 30s / 30s.

**user_agent_hide_computer_name**

Set to ``1`` to prevent the computer name from being sent as part of the User-Agent header in HTTP requests to the privacyIDEA server.

-----------------
Recovery Settings
-----------------

**fallback_hostname, fallback_path, fallback_port**

These settings allow you to specify a fallback URL. If at least the fallback hostname is set, it will be used if the primary hostname is unavailable. Once that happens, the fallback setting will be used for the rest of the authentication session.

**excluded_account**

Specify an account that should be excluded from 2FA. The format is required to be ``domain\username`` or ``computername\username``.

**excluded_group**

Specify a group whose members are excluded from 2FA. Can be a local, global, or nested group.

.. note:: Global groups require **excluded_group_netbios_address** to be set.

**excluded_group_netbios_address**

The NetBIOS address of the computer to query for global groups. For example, you can get a list of candidates by running ``netdom query dc``, which will give you a list of Domain Controllers.

---------------------------------
Login Behavior and User Interface
---------------------------------

Using these settings you can specify the behavior and UI of the privacyIDEA Credential Provider. By default, the Credential Provider will prompt for username -> MFA -> password. Optionally, you can set it to username+password, then MFA.

**v1_bitmap_path**

The complete path and filename of a bitmap image. This is a customized login image. The image must be a version 3 Windows BMP file with a resolution of 128x128 pixels.

**username_password**

Set to ``1`` if the privacyIDEA Credential Provider will prompt for username and password in the first step.

**two_step_send_password**

Set to ``1`` if the privacyIDEA Credential Provider should send the user's password to privacyIDEA, potentially triggering tokens. This can be useful with the policy ``otppin=userstore``. If this is enabled, the Credential Provider will automatically prompt for username and password in the first step.

**two_step_send_empty_password**

Set to ``1`` if the privacyIDEA Credential Provider should send an empty password to the privacyIDEA Authentication Service. Enabling this will **not** cause the Credential Provider to automatically prompt for username and password in the first step.

.. note:: If both **two_step_send_password** and **two_step_send_empty_password** are set to ``1``, the privacyIDEA Credential Provider will send an empty password to privacyIDEA.

**send_upn**

Set to ``1`` to send the UPN instead of the username and domain to privacyIDEA. The determination of whether the username input is a UPN is currently basic; it assumes a UPN if the input contains an ``@`` and no ``\``. If the input is not a UPN, the usual realm settings are applied.

**resolve_upn**

Set to ``1`` to attempt to resolve User Principal Names (UPN) (e.g., ``user@domain.com``) to the NetBIOS format (``DOMAIN\user``) using the Windows ``TranslateName`` API. This is useful in scenarios where the UPN suffix (e.g., ``.com``) does not match the internal local domain name (e.g., ``.local``).

.. warning::
   This may introduce latency during login if the Domain Controller is unreachable.

**hide_domainname**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide only the domain name when the desktop is locked.

**hide_fullname**

Set to ``1`` if you want the privacyIDEA Credential Provider to hide the user and domain name when the desktop is locked. Instead, only the contents of the *login_text* settings will be displayed.

**no_default**

Add this registry entry and set it to ``1`` to **not** have the privacyIDEA Credential Provider selected by default when logging in. This will only have an effect if there are other credential providers available.

**show_domain_hint**

Set this to ``1`` to show the domain that is currently used to log in.

**prefill_username**

Set this to ``1`` to have the username field prefilled with the user that last logged on.

**enable_reset**

Set this to ``1`` to have a clickable text shown at the bottom which will reset the login.

**otp_fail_return_to_first_step**

Set to ``1`` to return to the first step after entering a wrong OTP. Default is ``0``, so after entering a wrong OTP, you are prompted for the OTP again.

**hide_first_step_response_error**

Set to ``1`` to hide the fail message, like "wrong OTP PIN", when using **two_step_send_empty_password** or **two_step_send_password** and no token has been triggered. Instead, the default prompt will be shown.

**header_accept_language**

Set this to a valid accept language header like "en-GB" or "de-DE". Alternatively, if left empty or the value is "system", the system language will be used. This header will be used in requests to privacyIDEA, and the messages privacyIDEA returns will be localized in that language if a translation is available and no active policy overrides the message.

-----------------
Customizing Texts
-----------------

Starting with version 3.7.0 of the Credential Provider, you can customize all texts used by the Credential Provider. You can also modify or add translations.

The translation files are installed to ``C:\ProgramData\Netknights GmbH\PrivacyIDEA Credential Provider\locales``. To edit these files, you need to change their permissions, or use "Take Ownership".

In previous versions of the Credential Provider, you could specify custom texts for specific UI elements. These settings have been superseded by the translation and customization system.

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

**localesPath**

Override the default path where the Credential Provider looks for translation files.

------------------------------------------
Filter and Scenario Specific Configuration
------------------------------------------

The Filter is an additional component of the credential provider. It can be used to filter out other credential providers (e.g., the system ones). By default, if our filter is enabled, it will filter every other credential provider so that the privacyIDEA Credential Provider is the only one available.

**enable_filter**

Set this to ``1`` to enable the filter of the privacyIDEA Credential Provider. If this is disabled, the privacyIDEA Credential Provider will be listed *in addition* to other existing credential providers.

**filter_whitelist**

Add entries to this REG_MULTI_SZ to spare other credential providers from being filtered. The entry has to be the CLSID of a CP.

One way to check the CLSID of a CP is to look at:
``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers``

There are different *credential provider usage scenarios* (``cpus``). The available scenarios are *logon*, *unlock*, and *credui*.

It is possible to configure both the Credential Provider and the Filter for each of the scenarios. This way, the administrator can define a different behavior whether a user logs in or unlocks their desktop. For the configurations in this section to take effect, the ``enable_filter`` setting must be enabled (v3.2 or higher).

The behavior in each scenario can be configured via the corresponding registry entry named **cpus_logon**, **cpus_unlock**, and **cpus_credui**.

These entries expect a ``REG_SZ`` consisting of a digit (0, 1, 2, or 3) and a character ('e' or 'd').

The digits stand for:

* 0: relevant for *remote* (RDP) and *local* operation
* 1: relevant for *remote* operation
* 2: relevant for *local* operation
* 3: the privacyIDEA Credential Provider will *not* be shown in remote and local operation.

The characters stand for:

* "e": Only the privacyIDEA Credential Provider is available. All other credential providers are not available.
* "d": The privacyIDEA Credential Provider will be available *in addition* to all other credential providers on the machine.

Examples:

* ``cpus_logon = 0e``: Only the privacyIDEA Credential Provider is available for Logon via remote and local sessions.
* ``cpus_unlock = 1d``: Remotely, the locked desktop can be unlocked with all available credential providers, including the privacyIDEA Credential Provider.
* ``cpus_unlock = 2e``: Locally, unlocking the desktop is only possible with the privacyIDEA Credential Provider.
* ``cpus_credui = 3d``: For credui scenarios, the privacyIDEA Credential Provider is disabled and will not be shown, no matter if remotely or locally. Only the other credential providers are available. (Note: "3e" is invalid, as it would leave no credential providers available.)

If there is no entry for a scenario, the default is assumed:
The privacyIDEA Credential Provider will be available and the Filter will be active, if installed.

.. note::
   Starting with Windows 10, CPUS_UNLOCK is not triggered by default anymore when unlocking the workstation. Instead, unlocking the workstation is considered CPUS_LOGON. If you need to differentiate the two scenarios, disabling fast user switching in the group policy editor restores the previous behavior. An example of how to do this can be found here: https://support.waters.com/KB_Inf/Empower_Breeze/WKB47366_How_To_Enable_Disable_Fast_User_Switching_In_Windows_10

.. note::
   To use the Credential Provider in CredUI Scenarios on Privileged Access Workstations with Admin Accounts, see: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4

----------------------------------------------
Recommended Setup for Remote Desktop Scenarios
----------------------------------------------

In scenarios where the privacyIDEA Credential Provider is to be used for RDP connections, it is recommended to install the privacyIDEA Credential Provider only on the RDP target. The Filter has to be enabled for RDP scenarios; otherwise, Windows will use the System Credential Provider automatically!

----
FIDO
----

The Credential Provider supports FIDO Authentication without EntraID. Starting with version 3.7.0, it also supports FIDO in RDP scenarios by using Windows Hello.

Currently, a passwordless login is not possible, as the Credential Provider Interface requires a username, domain, and password for the login. We are working on providing a solution for this. To use a passkey (and thus a usernameless login), simply click the link at the bottom to initiate the login with a passkey. This will cover the username and MFA step in one, and the Credential Provider will prompt for the password in the last step.

Because a password (knowledge factor) is still required here, you can disable the *user_verification* (the prompt for the PIN of the security key) for the Credential Provider by creating a policy with ``webauthn_user_verification_requirement=discouraged`` in privacyIDEA. It is advised to use this policy only for the Credential Provider (e.g., by setting a condition on the User-Agent or IP). In other cases where passwordless login is possible, using this policy would result in a login with only one factor (ownership of the security key) and no knowledge factor (PIN/password).

However, a specific behavior arises if a security key holds **multiple credentials** for the same Relying Party (RP ID). To display a selection list, the Credential Provider needs to retrieve the usernames associated with the credentials. Most FIDO2 devices treat this user metadata as sensitive information and protect it behind the PIN. If you set ``webauthn_user_verification_requirement=discouraged``, the user experiences a "double tap" flow:

1. **First Tap:** The user taps the key without a PIN (honoring the policy). The device confirms valid credentials exist but refuses to release the usernames.
2. **Escalation:** The Credential Provider detects the ambiguity and is forced to request the PIN to "unlock" the names.
3. **Second Tap:** The user enters the PIN and taps again. The device returns the usernames, and the selection list appears.

**Recommendation:** If you expect users to have multiple credentials on a single key, avoid the ``discouraged`` setting. Leaving User Verification as ``preferred`` or ``required`` ensures the PIN is requested immediately, allowing the selection list to populate after a single tap.

To use WebAuthn tokens, it is required to configure **two_step_send_empty_password** or **two_step_send_password** to trigger a challenge! WebAuthn tokens are not usernameless. By default, Passkey tokens can *not* be triggered like WebAuthn tokens. You can set the policy ``passkey_trigger_by_pin=true`` in privacyIDEA to have Passkeys behave like WebAuthn tokens, and the Credential Provider is able to handle that as well.

.. warning::
   After you are prompted to touch your security key, it is not possible to cancel the operation. Even though there is a cancel button, control is transferred to the device until the operation is completed or times out!

.. note::
   Windows Hello is not supported for local logins because the UI cannot be rendered in Logon/Unlock scenarios. To use FIDO in RDP scenarios, only Windows Hello will be used, because it handles the tunneling of the FIDO data to the local device.

**passkey_first_step**

Set to ``1`` to have the Credential Provider start immediately in Passkey mode (Usernameless). Instead of seeing the Username/Password fields, the user will be prompted to touch their security key immediately. If the initialization fails (e.g., server unreachable), it falls back to the standard login fields.

**disable_passkey**

Set to ``1`` to disable the option to log in with a passkey, that is offered in the first step.

**webauthn_preferred**

Set to ``1`` to continue directly with webauthn mode after receiving a webauthn challenge. By default, the second step is OTP mode.

**webauthn_offline_no_pin**

Set this to ``1`` to not be prompted for the security key PIN when doing offline authentication with WebAuthn or Passkey. Online authentications remain controlled by privacyIDEA.

**webauthn_offline_second_step**

Set this to ``1`` to have the clickable link for a FIDO Authentication in the second step (privacyIDEA), in addition to the first step, which is enabled by default. In an offline scenario, the user can then enter their username (+password), press enter, and then will be offered to use the security key, just as if a FIDO token had been triggered if the machine was online. If an online FIDO authentication has been triggered, this will obviously have no effect. If this setting has an effect, the link in the second step will use the same text as the online one would, so it looks the same to the user.

**webauthn_offline_preferred**

Set this to ``1`` to go directly to security key mode if **webauthn_offline_second_step** was used. Analogous to **webauthn_preferred**, but dedicated for offline authentications.

**webauthn_offline_hide_first_step**

Set this to ``1`` to hide the offline FIDO link in the first step.

**disable_windows_hello_for_credui**

Set to ``1`` to disable the usage of Windows Hello for Credential UI scenarios (e.g., UAC prompts or other application authentication requests). Windows Hello is enabled by default in these scenarios to allow FIDO authentication.

**trusted_rpids**

A ``REG_MULTI_SZ`` list of Relying Party IDs that are trusted for FIDO operations. If this list is not empty, the Credential Provider will only allow FIDO operations for RP IDs contained in this list.

**libfido_debug**

Set to ``1`` to enable internal debug logging for the underlying ``libfido2`` library. This is useful for troubleshooting hardware compatibility issues.

--------------
Offline Tokens
--------------

HOTP and FIDO (WebAuthn and Passkey) tokens can be configured to be usable without a connection to privacyIDEA. On the detail page of the token in privacyIDEA, select Application => Offline at the bottom. Now the token has to be used online once with the Credential Provider to retrieve the configured amount of OTPs in advance.

Using HOTP offline is no longer recommended because the token becomes unusable for online authentication or on any machine other than the one holding the offline values. FIDO tokens do not have this restriction and can be used for online and offline authentications simultaneously. The offline data of a FIDO token can also reside on multiple devices.

The following settings can be useful with offline tokens:

**offline_file**

Specify the **absolute** path to where the offline file should be saved. The default is ``C:\offlineFile.json``.

.. note::
   Either a .txt or .json file type is recommended. The data that is saved is in JSON format.

**offline_try_window**

Specify how many offline values shall be compared to the input at max. Default is 10. A value of 0 equals the default.

**offline_threshold**

Specify the number of remaining OTP values below which a refill should be attempted. Refilling is done online and therefore requires a connection to the server. If the machine is really offline and a refill is attempted, this will cause a timeout and thus slow down the login. By default, a refill is attempted after every successful offline authentication. However, if 100 offline values are available, it is not necessary to try refilling after every authentication.

**offline_show_info**

Set this to ``1`` to show information about available offline tokens for the current user. This will trigger as soon as the input from the username field matches a user for which offline tokens are available.

**offline_expiration_days**

Sets the number of days an offline token remains valid after a successful online refill. Once this period elapses, the token is considered "expired" and cannot be used for offline authentication. However, the data remains in the offline file and can be reactivated (refilled) automatically if the user logs in online. Default is ``0``, which means the offline token never expires.

**offline_delete_after_days**

Sets the number of days *after expiration* that a stale token is retained before being permanently deleted. This acts as a garbage collection mechanism. The calculation is relative to the expiration date: ``Deletion Date = Expiration Date + offline_delete_after_days``. Default is ``0``, which means stale tokens are never deleted.

**check_all_offline_credentials**

Set to ``1`` to validate all offline credentials against the server during login, instead of just the credentials for the current user. This is useful for "garbage collection" of old tokens from multiple users on shared machines.

------
Realms
------

Realms are implemented by mapping Windows domains to privacyIDEA realms. When a matching mapping exists, the &realm=... parameter is added to the request.

**default_realm**

Specify a default realm. If set, it is appended to every request that has no other matching mapping. The mapping is done in the sub-key ``realm-mapping`` (``Computer\HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-CP\realm-mapping``). Here, you can specify the Windows domains as the names and the privacyIDEA realms as the data of ``REG_SZ`` entries.

-------
Logging
-------

**debug_log**

Set to ``1`` if you want the privacyIDEA Credential Provider to write a detailed log file, which is helpful when reporting bugs. The log file is located at ``C:\PICredentialProviderLog.txt``. If this setting is disabled, actual errors are still written to the log file.

**log_sensitive**

In some cases, it can be useful to log sensitive data (e.g., passwords) to find the cause of a problem. By default, sensitive data is not logged. Instead, it is only logged if the password contains a value. To log sensitive data as well, create a new registry key of type ``REG_SZ`` with the name ``log_sensitive`` and a value of ``1``. This can be deleted after creating a log file.

---------
AutoLogon
---------

Windows has an AutoLogon Feature (https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) which is a security risk and should not be used. The privacyIDEA Credential Provider can do the same, but it is discouraged, so use it at your own peril!

You need to create the following entries: ``autologon_username``, ``autologon_domain``, and ``autologon_password``, and set them to the corresponding values. Only if all three of these are set will the AutoLogon be enabled.
