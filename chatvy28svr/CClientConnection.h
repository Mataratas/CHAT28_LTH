#pragma once
#include "../netcommon.h"
#include "CDBAccess.h"
//===============================================================================================
class CClientConnection{
public:
#ifdef __linux__
	CClientConnection(int s, char* ip, std::shared_ptr<DBCTX>, std::shared_ptr<LOG>);
	auto get_socket() -> int const { return _socket; };
	auto send_to_client(int, IOMSG&) -> bool;
	auto process_client_msg(int, IOMSG&, bool&) -> bool;
#elif defined(_WIN64) || defined(_WIN32)
	CClientConnection(SOCKET s, char* ip, std::shared_ptr<DBCTX>, std::shared_ptr<LOG>);
	auto get_socket() -> SOCKET const { return _socket; };
	auto get_ip() -> char* const { return _s_ip; };
	auto send_to_client(SOCKET, IOMSG&) -> bool;
	auto process_client_msg(SOCKET, IOMSG&, bool&) -> bool;
#endif	
	CClientConnection(const CClientConnection&);
	CClientConnection(CClientConnection&&);
	~CClientConnection();
	typedef std::shared_ptr<CClientConnection> CLCPtr;

private:
	auto _login_used(const std::string&) -> bool;
	auto _is_valid_user_pwd(const std::string& pwd) -> bool;
	char _s_ip[15]{ '\0' };
#ifdef __linux__
	int _socket{ -1 };
#elif defined(_WIN64) || defined(_WIN32)
	SOCKET _socket{ INVALID_SOCKET };
#endif
	uint64_t _usr_db_id{};
	std::string _user, _pwd_hash;
	std::shared_ptr<DBCTX>_hDB;
	std::shared_ptr<CUser> _user_ptr;
	std::map<std::string, std::shared_ptr<CMessage>> _msg_pool;
	std::shared_ptr<LOG> _log_ptr;
	std::shared_mutex _mtxs;
	std::vector<std::string> _buffer;
};

using CLC = CClientConnection;

