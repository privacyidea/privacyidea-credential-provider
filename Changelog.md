# Version 3.7.0 2024-08-05
This version introduces a few changes, especially in the order the user is prompted for inputs. Please take a moment to read the [updated configuration documentation](https://github.com/privacyidea/privacyidea-credential-provider/blob/master/doc/configuration.rst).
## Summary of Changes
The default order of prompts is now username -> MFA -> password. This allows for a meaningful usernameless passkey login. While the password is still required, the Credential Provider is prepared for a solution that does not need the password input from the user. 

Alternatively, you can configure the flow to be username+password -> MFA. **The option to have username+password+OTP in a single step has been removed.**

All texts that have been configurable via dedicated registry entries are now configurable via the translation system. If you previously used one of these customized texts, please see the documentation on how to do it with the new system. There is also information on which old registry entry corresponds to which message ID.

Installing this version will remove unused registry entries automatically.

## Features
* Passkey Login, allowing a usernameless FIDO authentication
* Passkey enrollment during authentication with the enroll_via_multichallenge policy
* Passkey offline
* Exluded Group to exclude a group of users from MFA

## Enhancements
* FIDO authentication and registration will now work properly in RDP scenarios using windows hello
* Configurable accept-language for http requests
* Fallback url
* Background thread that does the polling when doing push authentication will now timeout after 5 minutes in case of ghost sessions
* `hide_first_step_response_error` to hide the message when sending an empty password or the password in the first step did not trigger a challenge
* Smartphone container can be enrolled with the enroll_via_multichallenge policy
* Added option to cancel enroll_via_multichallenge enrollments with privacyIDEA 3.12+
* Added `register for safe mode` to installer
* Updated installer to reflect most of the new configuration options and removed old options

## Fixes
* Fixed a bug where `prefill_username` would still overwrite another username that was entered after the field was prefilled, resulting in a logon attempt of the wrong user.
* Fixed implementation of GET requests so that polling for push authentications works with privacyIDEA 3.11 and higher


# Version 3.6.0 2024-08-09

## Enhancement
* WebAuthn via NFC. However, this feature is marked as experimental by libfido2, which is used here. So there might be devices that do not work or other problems.
* WebAuthn token can be used for offline authentication if it is marked as such in privacyIDEA.
* Use of `user_verification=discouraged` policy in privacyIDEA is now considered. In offline scenarios, the PIN prompt can be controlled via `webauthn_offline_no_pin` registry setting.
* Changed translation system to allow adding or changing translations without the need to install a new version. Also added spanish translation. Both contributed by charlyR (#158)

## Fixes
* Fixed a bug that would cause `otp_link_text` to be ignored.
* Fixed a bug that would cause the (customizable) OTP failure text to not be displayed.


# Version 3.5.4 2024-06-20

## Enhancement
* `otp_fail_return_to_first_step` can be set to `1` to return to the first step (username and password) after the OTP verification failed. The default behavior is to stay in the second step and ask for the OTP again.

## Fixes
* Fixed a bug that would result in the reset_link being invisible after clicking it once
* Fixed unintended behavior with some combinations of the reset link, offline info and deselecting the credential tile
* Fixed a bug that would cause the transactionid to be lost for consecutive requests
* Duplicated messages prompting for the OTP are removed.


# Version 3.5.3 2024-03-25

## Fixes
* Fixed a bug that would result in `two_step_hide_otp` being ignored when selecting another credential provider
* Fixed a bug that would not reset the login to the first step if "the user could not be found in any resolver in this realm" occured
* Fixed a bug that would prevent the FIDO device recognition on the second try if it was cancelled once


# Version 3.5.2 2024-03-18

## Fixes
* Fixed inverted German-English translation that occured for some texts


# Version 3.5.1 2024-03-05

## Fixes
* Fixed successful offline authentication with HOTP not ending the authentication
* Fixed the info text displayed for offline token for webauthn
* Fixed refreshing of refilltoken for webauthn offline
* Fixed FIDO device search cancellation
* Fixed some texts
* Added texts for refill phases to be distinguished from authentication


# Version 3.5.0 2024-02-20

## Features
* WebAuthn online
* WebAuthn offline, requires privacyIDEA 3.10

## Enhancements
* Added CredentialProvider version to the useragent
* Added ComputerName to useragent (optional). This will be needed for the WebAuthn offline management of refilltoken in the server.

## Fixes
* Fixed `reset_link_text` to be actually used when set
* Fixed a bug when using RDP with UPN would result in the UPN not being split properly and therefore producing a wrong username, making login impossible.


# Version 3.4.0 2023-06-26

## Features
* If 'send_upn' is enabled and the username input contains an '@' and no '\', it will be send as is to privacyidea. This feature does not *yet* check with AD if the UPN is correct.

## Fixes
* Fixed a bug where a password reset for an expired password was not recogized.
* Fixed a bug where the '%' was not properly encoded when communicating with privacyidea.


# Version 3.3.0, 2023-02-20

## Features
* Token enrollment via challenge-response (introduced in privacyIDEA 3.8) can be used in the CP.
* Added whitelist for the filter to spare other credential providers from being filtered.

## Fixes
* If sending password or emtpy password was enabled and machine was offline, it was impossible to get to the second step for an offline authentication, because of the error caused by the attempt to send something. This is now fixed and offline is possible even if an error occured in the first step.
* If the excluded_account included a '.', it was not resolved to the local machine name before comparing with the input. Now both input and registry setting will have the '.' resolved before comparing values.


# Version 3.2.2, 2022-10-23

## Fixes

* Remember the serial of the token that was used to authenticate to add the refill values to the right token, fixes #123
* If prefill_username is enabled, set the focus to the password field, fixes #122
* Update the offline info after wrong password or other errors. The number displayed will now represent the comsumed offline 	OTPs if they had not been refilled directly (e.g. machine is offline)
* Fixed the count field in the offline file to correctly display the count of OTPs

# Version 3.2.1, 2022-09-23

## Fixes
* Fixed a bug where an offline user would not be found if the username was capitalized differently (missing case insensitivity)
* When entering the wrong OTP in RDP scenarios, the credential provider will now reset to the first step with username and password prefilled. This way, the user just has to press enter and can trigger challenges again.
*Fixed a bug where the installer wrote the wrong values for scenario specific configuration


# Version 3.2.0, 2022-05-03

## Features
 * Multiple offline token for multiple users are possible now
 * Added "offline_threshold" configuration entry. OfflineRefill is only attempted when the remaining offline OTPs drop below the threshold. This will prevent having to wait for a connection timeout every time a authentication is performed where the computer is really offline.
 * Added "offline_show_info" configuration entry. This will display available offline token for the user that is currently logging.
 * Added "enable_filter" configuration entry. This will enable the filter (which removes all other Credential Providers).
 * Updated the installer with more configuration possibilities. Moreover, the filter is now always installed and has to be activated via the configuration of this Credential Provider.

## Fixes
 * When using RDP, the incoming password is now properly decrypted so that "2step_send_password" works correctly in this scenario.
 * Fixed a bug that could cause an infinite loop in the CredUI scenario.
 * Improved the "show_domain_hint" feature to directly show the domain that will be used when entering a backslash.
 * Entering '.\' will now be properly resolved to the local computer name.
 * Entering '@' will now be handled correctly to indicate a domain.
 * Failing the 2nd factor check in RDP scenarios will now only reset the 2nd step. In RDP scenarios, the username and password are already checked before connecting, therefore it is not required to check those on the target again.

# Version 3.1.2, 2021-06-09

## Features
 * Added "enable_reset" configuration setting to show a clickable text at the bottom that resets the login.
 * Added "debug_log" configuration setting to create a detailed log file. This setting replaces "release_log", real errors are always written to the log file. This setting also removes the need to install the debug version to create a detailed log.
 * Added status callback to WinHttp to get more detailed information about certain failures.
 
 ## Fixes
 * Fixed crash when deselecting the Credential Provider tile.
 * Fixed missing lookup of "no_default" setting.
 * The installer now writes all possible configuration keys to the registry. The configurable parts in the installer are unchanged.

# Version 3.1.1, 2021-05-07

## Features
 * Added "prefill_username" configuration setting to prefill the username field with the last user that logged on

## Fixes
 * Fix loading custom bitmaps as custom tile picture.
 * Fix WinHttp default timeouts

# Version 3.1.0, 2020-09-29

## Features
 * The behavior of the CP and Filter can be modified for each scenario separately (see docs).

## Enhancements

## Fixes
 * Fix missing Submit button upon failure when 2step is enabled.


# Version 3.0.0, 2020-05-28

## Features
 * Support realms by configuring a realm mapping in the registry
 * Support of Push Token
 * Support offline authentication
 * Support exclusion of a single account

## Enhancements

## Fixes


# Version 2.5.2, 2019-08-02

## Fixes
 * Fix for clients experiencing a freeze when using only hide_otp configuration.
 * URL encoding of parameters which are sent to the server.

# Version 2.5.1, 2018-11-26

### Fixes

 * Fix buffer overflow in certain RDP scenarios, that crashes the terminal server client.
 * Make default tile configurable via NO_DEFAULT='1' registry key.


# Version 2.5.0, 2018-10-15

### Features
 *	Support SMS/Email tokens, which require a transaction id to be appended to the request. This only works when the CP is configured to ask for the OTP in a second step.
	The message of the challenge is displayed to the user.
	
### Enhancements
 *	Logging of sensitive data can be activiated by a registry key
 
### Fixes
 *	Fix missing lookup of the domain when using over-the-shoulder-prompting (UAC).
	Note: The UAC scenario with the credential provider does currently not work on Windows 8/ Server 2012.
 
# Version 2.4.0, 2018-09-13

### Features
 *	Password change on a locked workstation is not possible. If this occurs, block our tile and guide the user to sign out and in again to
	complete the password change in the LOGON scenario. (Similar to what Windows does)
	
### Enhancements

### Fixes


# Version 2.3.3, 2018-08-21

### Features
 * Optionally send an empty password or the domain password to the privacyIDEA server.
   (As intended in version 2.0)
   This is only possible if the request for the OTP is made in a second step.

### Enhancements
 * Added icon to display in installed software list
 * Improved debug message format
 * More debug messages
 * Changed version number format to end with buildnumber
 
### Fixes
 * Displaying the correct version number in the MSI as well as in the installed software list
 * Removed unnecessary communication with the privacyIDEA server

# Version 2.3.2, 2018-08-19

### Features
* Support changing the password on logon if the password expired or is requested to change by the admin

### Enhancements

### Fixes


# Version 2.3.1, 2018-07-19

### Features
  * Optional registry key for custom ports

### Enhancements
 * Adjusted Installer

### Fixes
  * Fixed a bug with parsing the path from the URL  

# Version 2.2, 2018-05-29

### Features
* Bugfix for URLs with scheme and paths specified
* Username and domain hideable on locked machines (custom login text will still be displayed)
* Custom OTP field text

### Enhancements
 * Adjusted Installer

### Fixes


# Version 2.1, 2018-05-07

### Features

### Enhancements
  
* When connecting to a machine with privacyIDEA CP, allow
  to use the credentials which were already passed in NLA.
  We only ask for OTP.

### Fixes


# Version 2.0, 2018-05-03

### Features
  * Replaced libcurl and OpenSSL with Winhttp
  * SSL errors can be ignored optionally
  * Second dialog to enter OTP separately
  * Optionally send the domain password to the privacyIDEA server
  
### Enhancements
  * Adjusted Installer
  * Add new logos
  * Cleanup license and README

### Fixes
  * Add correct user-agent
