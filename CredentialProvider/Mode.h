#pragma once

enum class Mode
{
	NO_CHANGE = 0,
	CHANGE_PASSWORD = 6,

	USERNAME = 10,
	PASSWORD = 11,
	USERNAMEPASSWORD = 12, // Required for send_pass.

	PRIVACYIDEA = 13,
	SEC_KEY_ANY = 15,
	PASSKEY = 16,

	SEC_KEY_REG = 17,
	SEC_KEY_REG_PIN = 18,

	SEC_KEY_PIN = 21,
	SEC_KEY_NO_PIN = 22, // Requires reset with autoLogon to get to CCredential::Connect directly
	SEC_KEY_NO_DEVICE = 23, // Requires reset with autoLogon to get to CCredential::Connect directly
};

template<typename... Modes>
constexpr bool IsModeOneOf(Mode mode, Modes... modes) noexcept
{
	return ((mode == modes) || ...);
}
