#include "pch.h"
#include "CppUnitTest.h"
#include "Configuration.h"
#pragma warning(disable : 4996)/*
#include "../CredentialProvider/core/CProvider.h"
#include "../CredentialProvider/core/CProvider.cpp"
#include "../CredentialProvider/core/CCredential.h"
#include "../CredentialProvider/core/CCredential.cpp"
#include "Configuration.h"
#include "Configuration.cpp"*/
#include "helpers.h"
#include "helpers.cpp"
#include "Dll.h"
#include "Dll.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Tests
{
	TEST_CLASS(Tests)
	{
	public:
		
		TEST_METHOD(TestMethod1)
		{
			Configuration conf;
			
		}
	};
}
