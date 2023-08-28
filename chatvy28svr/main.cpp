#include "CTCPServer.h"
//======================================================================================
int main(int argc, char** argv) {
	print_os_data();	
	std::string log_path{ argv[0] };
	auto pos = log_path.find_last_of('.');
	log_path = log_path.substr(0,pos);

	TSPS CS(log_path.c_str());
	if (!CS.init_ok())
		std::cout << BOLDRED << "\nFailed to run chat server\n" << RESET << std::endl;
	else 
		if (CS.process_clients());

	return 0;
}
//======================================================================================
