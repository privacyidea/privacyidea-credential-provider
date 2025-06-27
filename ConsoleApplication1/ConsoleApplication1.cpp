#include <iostream>
#include "../CppClient/CppClient/FIDO2Device.h"
#include <thread>
#include <chrono>

int main()
{
	std::vector<FIDO2Device> devices;
	while (true)
	{
		devices = FIDO2Device::GetDevices();
		if (devices.size() > 0)
		{
			break;
		}
		std::cout << "No FIDO2 devices found. Please connect a device." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}
	
	auto dev = devices[0];

	

}
