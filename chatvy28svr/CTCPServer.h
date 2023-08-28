#pragma once
#include "CClientConnection.h"
#include "CDBAccess.h"
#include <chrono>


#if defined(_WIN64) || defined(_WIN32)
#pragma comment (lib, "Ws2_32.lib")
#endif

#include "../utils.h"

//==================================================================================================
class CTCPServer{
public:
	CTCPServer(const char*);
	~CTCPServer();
	auto process_clients()-> bool;
	auto th_process_client(const CLC::CLCPtr&,bool&) -> void;
	auto init_ok()->bool const { return !_err_cnt;};
private:
	
#if defined(_WIN64) || defined(_WIN32)
	SOCKET _socket{ INVALID_SOCKET };
	WSAData _wData;
#elif defined(__linux__)
	int _socket{-1};	
#endif
	std::string _name{ "localhost" };
	size_t _err_cnt{};
	std::shared_ptr<DBCTX>_hDB;
	size_t _active_conns{ 0 };
	std::map<std::string, std::shared_ptr<CMessage>> _msg_pool;
	std::shared_ptr<LOG> _log_ptr;
	auto _db_init() -> bool;
	auto _hash_func(const std::string&) -> size_t;

};

using TSPS = CTCPServer;


