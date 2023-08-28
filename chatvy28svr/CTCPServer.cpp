#include "CTCPServer.h"
//================================================================================================================
CTCPServer::CTCPServer(const char* mod_name) {
	if(!_db_init()) _err_cnt++;
	if (!_err_cnt) {
		std::string err_descr;
		_log_ptr = std::make_shared<LOG>(mod_name);
#ifdef __linux__
		struct sockaddr_in svr_adress,_client_adress;
		_socket = socket(AF_INET, SOCK_STREAM, 0);
		if (_socket < 0) {
			_err_cnt++;
			err_descr = "Could not create socket: "; err_descr += strerror(errno);
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr);
			return;
		}

		const int enable = 1;
		socklen_t cl_length{ sizeof(_client_adress) };

		int iResult = setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
		if (iResult < 0) {
			close(_socket);
			err_descr = "Could not set the socket option: "; err_descr += strerror(errno);
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr);
			_err_cnt++;
			return;
		}
		memset(&svr_adress, 0, sizeof(svr_adress));

		svr_adress.sin_family = AF_INET;
		svr_adress.sin_addr.s_addr = htonl(INADDR_ANY);
		svr_adress.sin_port = htons(PORT);

		if (bind(_socket, (struct sockaddr*)&svr_adress, sizeof(svr_adress)) < 0) {
			close(_socket);
			err_descr = "Could not bind the address: "; err_descr += strerror(errno);
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr);
			_err_cnt++;
			return;
		}
		if (listen(_socket, SOMAXCONN) < 0) {
			close(_socket);
			err_descr = "Could not set the backlog: "; err_descr += strerror(errno);
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr);
			_err_cnt++;
			return;
		}else {
			std::cout << "Server is listening...\n";
		}
	
#elif defined(_WIN64) || defined(_WIN32)
		WSADATA _WSA;
		int iRes = WSAStartup(MAKEWORD(2, 2), &_WSA);

		if (iRes) {
			err_descr = "WSA init failed : "; err_descr += str_wsa_error(iRes);
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());
			exit(1);
		}
		struct addrinfo* result = NULL, * ptr = NULL, hints;
		BOOL bOptVal = FALSE;
		int bOptLen = sizeof(BOOL);
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		// Resolve the local address and port to be used by the server
		iRes = getaddrinfo(NULL, PORT, &hints, &result);
		if (iRes != 0) {
			err_descr = "getaddrinfo failed: "; err_descr += str_wsa_error(iRes);
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());
			WSACleanup();
			_err_cnt++;
			return;
		}

		// Create a SOCKET for the server to listen for client connections
		_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
		if (_socket == INVALID_SOCKET) {
			err_descr = "Error creating server socket(): "; err_descr += str_wsa_error(WSAGetLastError());
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());
			freeaddrinfo(result);
			WSACleanup();
			_err_cnt++;
			return;
		}

		// Setup the TCP listening socket
		iRes = setsockopt(_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&bOptVal, bOptLen);
		if (iRes == SOCKET_ERROR) {
			err_descr = "setsockopt for SO_EXCLUSIVEADDRUSE failed with error: "; err_descr += str_wsa_error(WSAGetLastError());
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());

			freeaddrinfo(result);
			closesocket(_socket);
			WSACleanup();
			_err_cnt++;
			return;
		}

		iRes = bind(_socket, static_cast<struct sockaddr*>(result->ai_addr), static_cast<int>(result->ai_addrlen));
		if (iRes == SOCKET_ERROR) {
			err_descr = "bind failed with error: "; err_descr += str_wsa_error(WSAGetLastError());
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());

			freeaddrinfo(result);
			closesocket(_socket);
			WSACleanup();
			_err_cnt++;
			return;
		}

		freeaddrinfo(result);
		if (listen(_socket, SOMAXCONN) == SOCKET_ERROR) {
			err_descr = "Listen failed with error: "; err_descr += str_wsa_error(WSAGetLastError());
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());

			closesocket(_socket);
			WSACleanup();
			_err_cnt++;
			return;
		}
		
		printf("The server is listening...\n");		
#endif
	}
}
//----------------------------------------------------------------------------------------------------------------
CTCPServer::~CTCPServer(){
#ifdef __linux__
	close(_socket);
#elif defined(_WIN64) || defined(_WIN32)
	closesocket(_socket);
	WSACleanup();
#endif
}
//----------------------------------------------------------------------------------------------------------------
auto CTCPServer::_db_init() -> bool {
	try {
		_hDB = std::make_shared<DBCTX>();
	}
	catch (const std::bad_alloc& ex) {
		std::string err_descr = "Failed to allocate memory for database context: "; err_descr += ex.what();
		std::cout << err_descr << std::endl;
		_log_ptr->write(err_descr.c_str());

		return false;
	}
	catch (...) {
		std::string err_descr = "Failed to init database..."; 
		std::cout << err_descr << std::endl;
		_log_ptr->write(err_descr.c_str());

		return false;
	}
	if (_hDB) {
#ifdef _DEBUG
		_hDB->show_version();
#endif // DEBUG
		if (!_hDB->init_ok()) {
			std::string err_descr = "DB not ready. Error code: "; err_descr += _hDB->get_last_error();
			std::cout << err_descr << std::endl;
			_log_ptr->write(err_descr.c_str());

			return false;
		}
	}else
		return false;

	return true;

}
//----------------------------------------------------------------------------------------------------------------
auto CTCPServer::th_process_client(const CLC::CLCPtr& cl_conn,bool& stop_server) ->void{
#ifdef _DEBUG
	std::cout << "thread #" << std::this_thread::get_id() << " [" << cl_conn->get_ip() << "]\n";
#endif // _DEBUG
	std::string info;
	bool exit_loop{ false };
	size_t bytes_in{};
	size_t buf_len{ sizeof(IOMSG) };
	char rcv_buf[sizeof(IOMSG)]{ '\0' };
	IOMSG _msg;
	uint8_t _msg_id{};

	while (!exit_loop) {
#ifdef __linux__
		bytes_in = read(cl_conn->get_socket(), rcv_buf, buf_len);
#elif defined(_WIN64) || defined(_WIN32)
		bytes_in = recv(cl_conn->get_socket(), rcv_buf, buf_len, 0);
#endif // __linux__
		if (bytes_in) {
			memcpy(&_msg, rcv_buf, buf_len);			
			if (cl_conn->process_client_msg(cl_conn->get_socket(), _msg, exit_loop))
				if (!cl_conn->send_to_client(cl_conn->get_socket(), _msg)) exit_loop = true;
			if (exit_loop) {
				info = "Session terminated.\n";
				break;
			}
		}
	}
#ifdef __linux__
	close(cl_conn->get_socket());
#elif defined(_WIN64) || defined(_WIN32)
	closesocket(cl_conn->get_socket());
#endif // __linux__
}
//----------------------------------------------------------------------------------------------------------------
auto CTCPServer::process_clients()->bool {
	if (_err_cnt)
		return false;
	std::string info;
	size_t bytes_in{}, bytes_out{}, iRet{};
	size_t buf_len{ sizeof(IOMSG) };
	char rcv_buf[sizeof(IOMSG)]{'\0'};
	bool stop_server{false};
	IOMSG _msg;
	uint8_t _msg_id{};

	while (!stop_server)
	{
#if defined(_WIN64) || defined(_WIN32)		
		SOCKET _cl_socket;
		SOCKADDR_IN addr_c;
#elif defined(__linux__) 
		int _cl_socket;
		struct sockaddr_in addr_c;
#endif
		char cl_ip[15]{(char)'/0'};
		int addrlen = sizeof(addr_c);
		_cl_socket = accept(_socket, (struct sockaddr*)&addr_c, &addrlen);

#ifdef __linux__
		if (_cl_socket < 0) {
			close(_socket);
			info = "Could not accept the client: "; info += strerror(errno);
			std::cout << info << std::endl;
			_log.write(info.c_str());

			_err_cnt++;
			return false;
		}
#elif defined(_WIN64) || defined(_WIN32)
		if (_cl_socket == INVALID_SOCKET) {

			info = "accept failed with error: "; info += str_wsa_error(WSAGetLastError());
			closesocket(_socket);
			WSACleanup();
			
			std::cout << info << std::endl;
			_log_ptr->write(info.c_str());

			_err_cnt++;
			return false;
		}
#endif // __linux__
		else {
#if defined(_WIN64) || defined(_WIN32)			
			char* WSAAPI cip = inet_ntoa(addr_c.sin_addr);
			if (cip) {
				info = "Incoming connection from client:"; info += cip;
				strcpy_s(cl_ip, cip);
			}else {
				info = "inet_ntoa failed with error"; info += str_wsa_error(WSAGetLastError());
			}

#else
			inet_ntop(AF_INET, &(addr_c.sin_addr), cl_ip, 15);
			info = "Incoming connection from client:"; info += cl_ip;
#endif	
			std::cout << BOLDCYAN << info << RESET << std::endl;
			_log_ptr->write(info.c_str());
		}

		CLC::CLCPtr client_connection(new CLC(_cl_socket, cl_ip,_hDB, _log_ptr));

		std::thread ct(&CTCPServer::th_process_client,this, client_connection, std::ref(stop_server));
		ct.detach();

	}
			
	return true;	
}
//----------------------------------------------------------------------------------------------------------------
auto CTCPServer::_hash_func(const std::string& user_name)->size_t {
	return cHasher{}(user_name);
}
//---------------------------------------------------------------------------


