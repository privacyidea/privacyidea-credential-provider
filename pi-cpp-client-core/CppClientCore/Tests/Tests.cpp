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
#define assertEquals(expected, actual)	 Assert::AreEqual(expected, actual)

#define _OUTPUT_TO_COUT

using namespace Microsoft::VisualStudio::CppUnitTestFramework;
using std::string;
using std::wstring;

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
			Assert::IsTrue(c.messagesEmpty());
			assertEquals(TTA::NOT_SET, c.tta);

			c.serial = "HOTP1";
			c.transaction_id = "1";
			c.tta = TTA::OTP;
			c.addMessage("message 1");
			c.addMessage("message 2");

			wstring msgs = L"message 1 or message 2:";
			assertEquals(msgs, c.getAggregatedMessage());

			string challengeToStr = "Challenge: serial=HOTP1, transaction_id=1, tta=OTP, messages=message 1, message 2";
			assertEquals(challengeToStr, c.toString());
		}

		TEST_METHOD(TestInit)
		{
			PICONFIG conf;
			conf.hostname = L"192.168.178.124";
			conf.ignoreInvalidCN = true;
			conf.ignoreUnknownCA = true;

			PrivacyIDEA pi(conf);
			pi.getLastErrorText();
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
		}
	};
}
