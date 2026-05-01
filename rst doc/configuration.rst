**two_step_send_password**

Set to ``1`` if the privacyIDEA Credential Provider should send the user's password to privacyIDEA, potentially triggering tokens. This can be useful with the policy ``otppin=userstore``. If this is enabled, the Credential Provider will automatically prompt for username and password in the first step.

**two_step_send_empty_password**

Set to ``1`` if the privacyIDEA Credential Provider should send an empty password to the privacyIDEA Authentication Service. Enabling this will **not** cause the Credential Provider to automatically prompt for username and password in the first step.

**two_step_expect_challenge**

Set to ``1`` if the Credential Provider should require a challenge (transaction ID) from the server after the first step in two-step authentication mode. When enabled, if the server returns a REJECT response without a ``transaction_id`` after the first step (when password or empty password is sent), the Credential Provider will treat it as a hard error and remain on the first step (password screen) instead of advancing to the OTP/WebAuthn screen. This is useful to ensure that authentication challenges are properly triggered before allowing the user to proceed to the second factor step.

.. note:: This setting only affects two-step authentication flows where ``two_step_send_password`` or ``two_step_send_empty_password`` is enabled.

**hide_otp**