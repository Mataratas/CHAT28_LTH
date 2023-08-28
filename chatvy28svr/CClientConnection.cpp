#include "CClientConnection.h"
//===============================================================================================
CClientConnection::CClientConnection(
#ifdef __linux__
	int s,
#elif defined(_WIN64) || defined(_WIN32)
	SOCKET s,
#endif
	char* ip, std::shared_ptr<DBCTX> hdb, std::shared_ptr<LOG> lptr) :_socket(s), _hDB(hdb), _log_ptr(lptr){
#ifdef __linux__
	strcpy(_s_ip, ip);
#elif defined(_WIN64) || defined(_WIN32)
	strcpy_s(_s_ip, ip);
#endif
};
//-----------------------------------------------------------------------------------------------
CClientConnection::CClientConnection(const CClientConnection& other) :_socket(other._socket), _usr_db_id(other._usr_db_id),_hDB(other._hDB), _log_ptr(other._log_ptr) {
#ifdef __linux__
	strcpy(_s_ip, other._s_ip);
#elif defined(_WIN64) || defined(_WIN32)
	strcpy_s(_s_ip, other._s_ip);
#endif
}
//-----------------------------------------------------------------------------------------------
CClientConnection::CClientConnection(CClientConnection&& rvc):_socket(rvc._socket), _usr_db_id(rvc._usr_db_id),_hDB(rvc._hDB) {
#ifdef __linux__
	strcpy(_s_ip, rvc._s_ip);
	rvc._socket = -1;
#elif defined(_WIN64) || defined(_WIN32)
	strcpy_s(_s_ip, rvc._s_ip);
	rvc._socket = INVALID_SOCKET;
#endif
	memset(rvc._s_ip, '\0', sizeof(rvc._s_ip));
	rvc._usr_db_id = 0;
};
//-----------------------------------------------------------------------------------------------
CClientConnection::~CClientConnection() {
}
//-----------------------------------------------------------------------------------------------
auto CClientConnection::process_client_msg(
#if defined(_WIN64) || defined(_WIN32)	
	SOCKET _cl_socket,
#elif defined(__linux__)
	int _cl_socket,
#endif
	IOMSG& in, bool& exit_loop) -> bool {

	bool existing_user{ false };
	switch (in.mtype) {
	case eAuth:
		in.mtype = eWelcome;
		memset(in.body, '\0', MSG_LENGTH);
		strcpy(in.body, "Welcome to chat session. New user?(y/n, x - exit):\n");
		break;
	case eNewUser:
		in.mtype = eChooseLogin;
		strcpy(in.body, "Choose your login(x - exit):\n");
		break;
	case eExistingUser:
		in.mtype = eLogin;
		strcpy(in.body, "Type your login(x - exit):\n");
		break;
	case eLogin:
		existing_user = *in.user == 'e';
		if (existing_user) {
			if (_login_used(in.body)) {
				_user = in.body;
				in.mtype = ePassword;
				strcpy(in.body, "Type your password(x - exit):\n");
			}
			else {
				in.mtype = eWrongLogin;
				strcpy(in.body, "Wrong login. Try again(x - exit):\n");
			}
		}
		else {
			if (_login_used(in.body)) {
				strcpy(in.body, "Login provided is already used. Choose another(x - exit):\n");
				in.mtype = eWrongLogin;
			}
			else {
				_user = in.body;
				in.mtype = eChoosePassword;
				strcpy(in.body, "Choose your password(x - exit):\n");
			}
		}
		break;
	case ePassword:
		existing_user = *in.user == 'e';
		if (existing_user) {
			std::string name, email, pwd_hash;
			uint64_t id;
			if (_hDB->get_user(_user.c_str(), id, name, email, pwd_hash)) {
				if (!strcmp(pwd_hash.c_str(), in.body)) {
					_user_ptr = std::make_shared<CUser>(_user.c_str(), in.body);
					_user_ptr->set_id(id);
					_usr_db_id = id;
					clear_message(in);

					in.mtype = eAuthOK;
					strcpy(in.body, "Login successful. (x - exit):\n");
					strcpy(in.user, std::to_string(_usr_db_id).c_str());
				}
				else {
					in.mtype = eWrongPassword;
					strcpy(in.body, "Invalid password. Type again(x - exit):\n");
				}
			}
			else {
				clear_message(in);
				in.mtype = eQuit;
				strcpy(in.body, "Server failed to reconfirm user existence:\n");

			}
		}
		else {
			if (*in.body == '\0') {
				in.mtype = eWrongPassword;
				strcpy(in.body, "Empty password not permited. Type one(x - exit):\n");
			}
			else {
				uint64_t id;
				if (_hDB->add_user(_user.c_str(), id)) {
					if (_hDB->set_user_pwdhash(id, in.body)) {
						_user_ptr = std::make_shared<CUser>(_user.c_str(), in.body);
						_user_ptr->set_id(id);
						_usr_db_id = id;
						clear_message(in);
						in.mtype = eAuthOK;
						strcpy(in.body, "Registration successful.\n");
						strcpy(in.user, std::to_string(_usr_db_id).c_str());
					}
					else {
						clear_message(in);
						in.mtype = eQuit;
						strcpy(in.body, "Failed to save user pwd:");
						strcat(in.body, _hDB->get_last_error());
						strcat(in.body, "\n");
					}

				}
				else {
					in.mtype = eQuit;
					memset(in.body, '\0', MSG_LENGTH);
					strcpy(in.body, "Failed to create user record in database!\n");
				}
			}
		}
		break;
	case eGetUserMsg:
		_hDB->get_user_msgs(_usr_db_id, _user, _msg_pool);
		if (_msg_pool.empty()) {
			clear_message(in);
			in.mtype = eNoMsg;
			strcpy(in.body, "You have no new messages.\n");
		}
		else {
			clear_message(in);
			auto curr_msg = _msg_pool.begin();
			in.mtype = eMsgNext;
			strcpy(in.body, curr_msg->second->serialize_msg().c_str());
			strcpy(in.user, "You have new messages:\n");
			_msg_pool.erase(curr_msg);
		}
		break;
	case eGetNextMsg:
		if (in.body) {
			//here body should contain a message id to be marked as viewed
			if (_hDB->set_msg_state(in.body, "2")) {
#ifdef _DEBUG
				std::cout << "Failed to change state of message with id:" << in.body << std::endl;
#endif // _DEBUG
			}
		}

		if (_msg_pool.empty()) {
			clear_message(in);
			in.mtype = eNoMsg;
		}
		else {
			clear_message(in);
			auto curr_msg = _msg_pool.begin();
			in.mtype = eMsgNext;
			strcpy(in.body, curr_msg->second->serialize_msg().c_str());
			_msg_pool.erase(curr_msg);
		}
		break;

	case eGetMainMenu:
		clear_message(in);
		in.mtype = eMsgMainMenu;
		strcpy(in.body, "Choose action : \n\twrite to user(u)\n\twrite to all(a)\n\tLog out(l)\n\tQuit(x) :\n");
		break;
	case eLogOut:
		_user.clear();
		_pwd_hash.clear();
		_usr_db_id = 0;
		in.mtype = eLogin;
		strcpy(in.body, "Type your login(x - exit):\n");
		break;

	case eSendToAll:
	{
		auto msg_sent = _hDB->deliver_msg(in.body, in.user);
		clear_message(in);
		in.mtype = eMsgDelivered;
		if (msg_sent) {
			strcpy(in.body, "messages sent OK\n");
		}
		else
			strcpy(in.body, "Failed to send messages\n");
		break;
	}
	case eSendToUser:
	{
		std::string available_users;
		if (!_hDB->pack_users(in.user, available_users)) {
			clear_message(in);
			in.mtype = eQuit;
			strcpy(in.body, "Sorry, no users available.\n");
		}
		else {
			in.mtype = eAvailableUsers;
			strcpy(in.body, available_users.c_str());
		}
		break;
	}
	case eSendToUserMsgReady:
	{
		if (_hDB->deliver_msg(in.body, std::to_string(_usr_db_id).c_str(), in.user)) {
			clear_message(in);
			in.mtype = eMsgDelivered;
			strcpy(in.body, "The message sent\n");
		}
		else {
			clear_message(in);
			in.mtype = eErrMsgNotDelivered;
			strcpy(in.body, "Failed to send message\n");
		}
		break;
	}
	case eQuit:
		_log_ptr->write("Client terminated connection");
		exit_loop = true;
		break;
	}

	return true;
}
//--------------------------------------------------------------------------------------
auto CClientConnection::send_to_client(
#if defined(_WIN64) || defined(_WIN32)	
	SOCKET _cl_socket,
#elif defined(__linux__)
	int _cl_socket,
#endif
	IOMSG& msg)->bool {
	size_t bytes_out{};
	std::string info;

#ifdef __linux__
	bytes_out = write(_cl_socket, reinterpret_cast<void*>(&msg), sizeof(IOMSG));
	if (!bytes_out) {
		close(_cl_socket);
		info = "Failed to send authorization request. Exiting..\n";
		std::cout << BOLDRED << info << RESET << std::endl;
		_log.write(info.c_str());

		return false;
	}

#elif defined(_WIN64) || defined(_WIN32)
	bytes_out = send(_cl_socket, reinterpret_cast<const char*>(&msg), sizeof(IOMSG), 0);
	if (bytes_out == SOCKET_ERROR) {
		info = "Failed to send message to server with error: "; info += str_wsa_error(WSAGetLastError());
		closesocket(_cl_socket);
		closesocket(_socket);
		WSACleanup();
		std::cout << BOLDRED << info << RESET << std::endl;
		_log_ptr->write(info.c_str());

		return false;
	}
#endif
	return true;
}
//--------------------------------------------------------------------------------------
auto CClientConnection::_login_used(const std::string& uname) -> bool {
	if (uname.size() && _hDB)
		return _hDB->login_used(uname.c_str());
	else
		return false;
}
//--------------------------------------------------------------------------------------
auto CClientConnection::_is_valid_user_pwd(const std::string& pwd) -> bool {
	return _hDB->user_pwdh_ok(_user.c_str(), pwd);
}
//--------------------------------------------------------------------------------------
