#pragma once
#ifdef __linux__
	#include <string.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <arpa/inet.h>
	#define PORT 55169
#elif defined(_WIN64) || defined(_WIN32)
	//#undef UNICODE
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <stdlib.h>
	#include <stdio.h>
	#define PORT "55169"
#endif // _WIN64 
#include <string>
#include<iostream>
#include<thread>

#pragma warning(disable : 5208)
#pragma warning(disable : 4996)

#define MSG_LENGTH 1024
#define USR_NAME_LEN 32

enum MessageTypes {
	//To send by client----------------------------------------------------------
	eAuth = 169,        //cl
	eNewUser,			//cl
	eExistingUser,		//cl
	eGetAvailableUsers,	//cl
	eGetUserMsg,        //cl
	eGetNextMsg,        //cl
	eGetMainMenu,       //cl
	eSendToAll,			//cl
	eSendToUser,		//cl
	eSendToUserMsgReady,//cl
	eLogOut,			//cl
	//To send by server----------------------------------------------------------
	eWelcome,			//srv
	eChooseLogin,       //srv
	eChoosePassword,	//srv
	eWrongLogin,		//srv
	eWrongPassword,		//srv
	eLoginUsed,			//srv
	eLoginOK,			//srv
	eAuthOK,			//srv
	eAvailableUsers,	//srv
	eMsgDelivered,		//srv
	eErrMsgNotDelivered,//srv
	eErrMsgBadFormat,	//srv 
	eNoMsg,				//srv
	eMsgNext,			//srv
	eMsgMainMenu,		//srv
	//To send by both----------------------------------------------------------
	eNone,				//cl-srv
	eLogin,				//cl-srv
	ePassword,			//cl-srv
	eQuit				//cl-srv
};
using MT = MessageTypes;
//-----------------------------------------------------------------------------------------
typedef struct {
	MT mtype{ eAuth };
	char body[MSG_LENGTH]{'\0'};
	char user[32]{'\0'};
}IOMSG;
//-----------------------------------------------------------------------------------------
static void clear_message(IOMSG& msg) {
	msg.mtype = eNone;
	memset(msg.body, '\0', MSG_LENGTH); 
	memset(msg.user, '\0', USR_NAME_LEN);
}
//-----------------------------------------------------------------------------------------
static void print_message(IOMSG& msg) {
	std::cout << "mtype: "<<msg.mtype << " body: " << msg.body << " user: " << msg.user << std::endl;
}
//-----------------------------------------------------------------------------------------
static auto str_wsa_error(size_t err)->const std::string {
#if defined(_WIN64) || defined(_WIN32)
	std::string res;
	switch (err) {
	case WSAENOTCONN:
		res = "The socket is not connected.\n";
		break;
	case WSAEINTR:
		res = "The (blocking) call was canceled through WSACancelBlockingCall.\n";
		break;
	case WSAEINPROGRESS:
		res = "A blocking Windows Sockets 1.1 call is in progress, or the service provider is still processing a callback function.\n";
		break;
	case WSAENETRESET:
		res = "The connection has been broken due to keep-alive activity that detected a failure while the operation was in progress.\n";
		break;
	case WSAESHUTDOWN:
		res = "The socket has been shut down\n";
		break;
	case WSAEWOULDBLOCK:
		res = "The socket is marked as nonblocking and the receive operation would block\n";
		break;
	}
	return res;
#else
	return "";
#endif
}
//----------------------------------------------------------------------------------------------------------------






