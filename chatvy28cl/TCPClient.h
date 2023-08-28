#pragma once
#include "../netcommon.h"
#include <map>
#include "CMessage.h"
#include "sha1.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#if defined(_WIN64) || defined(_WIN32)
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#endif // defined(_WIN64) || defined(_WIN32)


#include "../utils.h"

//#pragma warning(disable : 5208)

//==================================================================================================
class TCPClient{
public:
	TCPClient();
	TCPClient(const char*);
	~TCPClient();
	void start();
	void set_peer(const char* p) { _srv_name = p; };
	auto create_pwd_hash(const std::string&) -> std::string;
	auto set_db_id(const uint64_t& id) { _usr_db_id = id; };
private:
#if defined(_WIN64) || defined(_WIN32)
	WSADATA _wsaData;
	SOCKET _socket{ INVALID_SOCKET };
#elif defined(__linux__)
	int _socket{-1};	
#endif
	
	int _last_err_code{ 0 };
	char _buffer[sizeof(IOMSG)]{'\0'};
	size_t _buf_len{ sizeof(IOMSG) };

	std::string _srv_name{"localhost"};
	auto _init() -> void;
	auto _unpack_available_users(const std::string&, std::map<size_t, std::string>&) -> void;
	auto _send_to_server(IOMSG&) -> bool;
	uint64_t _usr_db_id{};

};

using TCPC = TCPClient;

