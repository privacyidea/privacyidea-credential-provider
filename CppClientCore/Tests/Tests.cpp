#include "pch.h"
#include "CppUnitTest.h"
#include "Challenge.h"
#include "PrivacyIDEA.h"
#include "Logger.h"
#include "Endpoint.h"
#include "OfflineData.h"
#include "OfflineHandler.h"
#include "CallbackTestClass.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <map>

#define assertEquals(expected, actual)	 Assert::AreEqual(expected, actual)

//#define _OUTPUT_TO_COUT

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using namespace std;
using nlohmann::json;

namespace Microsoft {
	namespace VisualStudio {
		namespace CppUnitTestFramework {
			template <>
			static std::wstring ToString<TTA>(const TTA& tta)
			{
				switch (tta)
				{
				case TTA::NOT_SET: return L"NOT_SET";
				case TTA::OTP: return L"OTP";
				case TTA::PUSH: return L"PUSH";
				case TTA::BOTH: return L"BOTH";
				}
				return std::wstring();
			}
		}
	}
}

namespace Tests
{
	TEST_CLASS(Tests)
	{
	public:

		TEST_METHOD(TestChallenge)
		{
			Challenge c;
			string emptyString = "";

			assertEquals(emptyString, c.serial);
			assertEquals(emptyString, c.transaction_id);
			Assert::IsTrue(c.message.empty());
			assertEquals(TTA::NOT_SET, c.tta);
		}

		TEST_METHOD(TestInit)
		{
			PICONFIG conf;
			conf.hostname = L"192.168.178.124";
			conf.ignoreInvalidCN = true;
			conf.ignoreUnknownCA = true;

			PrivacyIDEA pi(conf);
			//pi.getLastErrorText();
		}

		TEST_METHOD(TestSecureString)
		{
			SecureString ss1("teststring");

			SecureWString sws1 = PrivacyIDEA::ss2sws(ss1);

			assertEquals(L"teststring", sws1.c_str());

			SecureString ss2 = PrivacyIDEA::sws2ss(sws1);

			assertEquals(ss1.c_str(), ss2.c_str());
		}

		TEST_METHOD(TestOffline)
		{
			// test100000, ...02, ... , ...04
			string s1 = "$pbkdf2-sha512$19000$Scl5TwmhtPae856zFgJgLA$ZQAqtqmGTf6IY0t9jg2MCgd92XzxdijFcT4BNVsvONNpHwZkiKsHrf0oeckS8rRQ9KWBdMwZsQzhu8PkpyXnbA",
				s2 = "$pbkdf2-sha512$19000$4Lx3bi1FiBHiXGutVYpRqg$9mPHGSh1Ylz0PTEMwJKFw6tB.avOfYhqJsEnl3KMF8vIE//YUrtwNs4IN6ZU4OeoxFZejebOTtxt8wZjp4140w",
				s3 = "$pbkdf2-sha512$19000$JATgHGNsDSEEIGRMqXXOmQ$Ub67KeNbwObsFk7mwTetNflwTOEKXMzJ5BTblZsu3bV4KAP1rEW6nUPfqLf6/f2yoNhpX1mCS3dt77EBKtJM.A",
				s4 = "$pbkdf2-sha512$25000$SSlF6L2XUurdG.N8LyVkTA$hDscUl2n5H84YjlE0Z8I94YR0NiCcCrI2weuFPR7XID6mxSzbZOTwMAeYCMPKPritj/VwZAenosNWGhByi16Ng",
				s5 = "$pbkdf2-sha512$25000$NWYMAeDcuzfGOGds7Z1zLg$wOYEQApbmRMVjmEv1hLqi.n4ZeSG0AsSIEIR7TqVuwL64XM0yePEqOn/ur7mOWzuo5ak.vZgwQeHwYM71Cjlfw";
			// TEST100000 ... 002
			string s00 = "$pbkdf2-sha512$19000$DgGA0FrL2ZsTIuS8txYCoA$HAAMTr34j5pMwMA9XZeuNtNbvHklY0axMKlceqdaCfYzdml9MBH05tgZqvrQToYqCHPDQoBD.GH5/UGvs7HF4g",
				s001 = "$pbkdf2-sha512$19000$wfifc07p3dvb.1.LcU6ptQ$NmnYnWMMc9KuCSDG5If94qGTmLekRF7Fn9rE4nDxCGuaXBasvEuIyEdp.h2RNqvjbsFd6A/U1T5/9eMC/7v9GQ",
				s002 = "$pbkdf2-sha512$19000$53zvvddai/He.x9DyJnTGg$aUapWKcp21B2eSQzVVKtv9e.9Xs3aoNxg30dgU6TjyzaaHZcUNpvz7Cqj6yeTFYi1nzQ151I2z8sZWjln1fyag";

			string refilltoken1 = "c045105a6e7ec7f525931bef369a973d33f2cc3f05e77b3e8dee925d1002bbe9314e5d57fc371318";
			string refilltoken2 = "df30509bd5e81c19d89475448b0fdaba085e54cc7190211f55f9cee041f08a00e63e4d79a7a8bcdf";
			string serial = "OATH00014663";
			// Shortened JSONs
			auto jInitial = R"({
				"detail": {"serial": "OATH00014663"},
				"auth_items" : 
					{"offline": [{"refilltoken": "c045105a6e7ec7f525931bef369a973d33f2cc3f05e77b3e8dee925d1002bbe9314e5d57fc371318",
				"username": "daemon",
				"response" : {"1": "$pbkdf2-sha512$19000$Scl5TwmhtPae856zFgJgLA$ZQAqtqmGTf6IY0t9jg2MCgd92XzxdijFcT4BNVsvONNpHwZkiKsHrf0oeckS8rRQ9KWBdMwZsQzhu8PkpyXnbA",
							"2": "$pbkdf2-sha512$19000$4Lx3bi1FiBHiXGutVYpRqg$9mPHGSh1Ylz0PTEMwJKFw6tB.avOfYhqJsEnl3KMF8vIE//YUrtwNs4IN6ZU4OeoxFZejebOTtxt8wZjp4140w",
							"3": "$pbkdf2-sha512$19000$JATgHGNsDSEEIGRMqXXOmQ$Ub67KeNbwObsFk7mwTetNflwTOEKXMzJ5BTblZsu3bV4KAP1rEW6nUPfqLf6/f2yoNhpX1mCS3dt77EBKtJM.A"				
					} }
				]
				}
				})"_json;

			auto jRefill = R"(
			{
                "auth_items": {"offline": [{"refilltoken": "df30509bd5e81c19d89475448b0fdaba085e54cc7190211f55f9cee041f08a00e63e4d79a7a8bcdf",
                                            "username": "daemon",
                                            "response": 
                                            { "4": "$pbkdf2-sha512$25000$SSlF6L2XUurdG.N8LyVkTA$hDscUl2n5H84YjlE0Z8I94YR0NiCcCrI2weuFPR7XID6mxSzbZOTwMAeYCMPKPritj/VwZAenosNWGhByi16Ng",
                                              "5": "$pbkdf2-sha512$25000$NWYMAeDcuzfGOGds7Z1zLg$wOYEQApbmRMVjmEv1hLqi.n4ZeSG0AsSIEIR7TqVuwL64XM0yePEqOn/ur7mOWzuo5ak.vZgwQeHwYM71Cjlfw"
                                            } } ]
                              }
			}	
			)"_json;


			wstring filepath = L".\\offline.json";
			remove(PrivacyIDEA::ws2s(filepath).c_str());

			OfflineHandler offline(filepath, 10);
			HRESULT res = offline.parseForOfflineData(jInitial.dump());
			assertEquals(S_OK, res);
			res = offline.isDataVailable("daemon");
			assertEquals(S_OK, res);
			int count = offline.getOfflineValuesLeft("daemon");
			assertEquals(3, count);
			res = offline.verifyOfflineOTP(L"test100000", "daemon");
			assertEquals(S_OK, res);
			// trying the same value again fails
			res = offline.verifyOfflineOTP(L"test100000", "daemon");
			assertEquals(E_FAIL, res);
			// One value used
			count = offline.getOfflineValuesLeft("daemon");
			assertEquals(2, count);

			// Prepare refill
			map<string, string> params = map<string, string>();
			res = offline.getRefillTokenAndSerial("daemon", params);
			assertEquals(S_OK, res);
			// Check params
			try
			{
				assertEquals(refilltoken1, params.at("refilltoken"));
				assertEquals(serial, params.at("serial"));
			}
			catch (const std::out_of_range & e)
			{
				UNREFERENCED_PARAMETER(e);
				Assert::Fail(L"Map has no value for the keys tested!");
			}

			// Test the refill
			res = offline.parseRefillResponse(jRefill.dump(), "daemon");
			assertEquals(S_OK, res);
			// After refilling, 4 values are available
			count = offline.getOfflineValuesLeft("daemon");
			assertEquals(4, count);

			// Check if the new refilltoken is set
			params.clear();
			res = offline.getRefillTokenAndSerial("daemon", params);
			assertEquals(S_OK, res);
			try
			{
				assertEquals(refilltoken2, params.at("refilltoken"));
			}
			catch (const std::out_of_range & e)
			{
				UNREFERENCED_PARAMETER(e);
				Assert::Fail(L"Map has no value for the keys tested!");
			}

			// Use the last value, all other values will be gone
			res = offline.verifyOfflineOTP(L"test100004", "daemon");
			assertEquals(S_OK, res);
			count = offline.getOfflineValuesLeft("daemon");
			assertEquals(0, count);

			// Test wrong inputs
			res = offline.isDataVailable("user");
			assertEquals(PI_OFFLINE_DATA_USER_NOT_FOUND, res);
			count = offline.getOfflineValuesLeft("user");
			assertEquals(-1, count);
			res = offline.verifyOfflineOTP(L"111111", "daemon");
			assertEquals(E_FAIL, res);
			res = offline.verifyOfflineOTP(L"1111111", "");
			assertEquals(E_FAIL, res);
			res = offline.verifyOfflineOTP(L"im no otp", "daemon");
			assertEquals(E_FAIL, res);
			res = offline.getRefillTokenAndSerial("user", params);
			assertEquals(PI_OFFLINE_DATA_USER_NOT_FOUND, res);
			res = offline.parseForOfflineData(string());
			assertEquals(E_FAIL, res);
			res = offline.parseForOfflineData("cant parse this");
			assertEquals(PI_JSON_PARSE_ERROR, res);
			// vv not a "wrong" input vv
			string authResponse = "{\"detail\": {\"message\": \"matching 1 tokens\", \"otplen\": 6, \"serial\": \"OATH0001A58E\", \"threadid\": 140366760421120, \"type\": \"hotp\"}, \"id\": 1, \"jsonrpc\": \"2.0\", \"result\": {\"status\": true, \"value\": true}, \"time\": 1579772486.3738062, \"version\": \"privacyIDEA 3.2.1\", \"versionnumber\": \"3.2.1\", \"signature\": \"rsa_sha256_pss:\"}";
			res = offline.parseForOfflineData(authResponse);
			assertEquals(PI_OFFLINE_NO_OFFLINE_DATA, res);
			res = offline.parseRefillResponse("cant parse this", "daemon");
			assertEquals(PI_JSON_PARSE_ERROR, res);

			// Reload the file
			offline.~OfflineHandler();
			OfflineHandler offline2(filepath, 10);
			count = offline2.getOfflineValuesLeft("daemon");
			assertEquals(0, count);
		}

		TEST_METHOD(TestAsyncPoll)
		{
			PICONFIG conf;
			conf.hostname = L"192.168.178.124";
			conf.ignoreInvalidCN = true;
			conf.ignoreUnknownCA = true;

			PrivacyIDEA pi(conf);
			CallbackTestClass ctc;
			pi.validateCheck("Administrator", "", "Passw0rd!2");
			Challenge c = pi.getCurrentChallenge();
			pi.asyncPollTransaction("Administrator", c.transaction_id,
				std::bind(&CallbackTestClass::callback, ctc, std::placeholders::_1));

			//std::this_thread::sleep_for(std::chrono::seconds(10));
		}
	};
}
