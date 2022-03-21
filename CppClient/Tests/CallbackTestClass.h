#pragma once
#include <iostream>

class CallbackTestClass
{
public:
	CallbackTestClass() = default;

	void callback(bool success)
	{
		std::cout << "Callback invoked with " << success << std::endl;
	} 
};

