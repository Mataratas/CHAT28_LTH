#include "TCPClient.h"
//======================================================================================
int main(int argc, char** argv) {
	if (argc < 2) {
		std::string path{ argv[0] };
#ifdef __linux__
		auto const pos = path.find_last_of('/');
#elif defined(_WIN64) || defined(_WIN32)
		auto const pos = path.find_last_of('\\');
#endif // __linux__
		std::cout << "Usage: " << path.substr(pos + 1) << " [server name/ip adress]" << std::endl;
		return 0;
	}else {
		TCPC CS(argv[1]);
		CS.start();
	}

	return 0;
}