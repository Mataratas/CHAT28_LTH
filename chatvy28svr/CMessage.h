#pragma once
#include <ctime>
#include "CUser.h"


class CMessage {
public:
	CMessage(const char* msg, const std::string& snd, const std::string& rcv) :body(msg), reciever(rcv), sender(snd) {};
	explicit CMessage(const char*);
	~CMessage() = default;
	CMessage(const CMessage&) = delete;
	CMessage& operator=(const CMessage&) = delete;
	friend std::ostream& operator<<(std::ostream& out, const CMessage&);
	template<class S> void set_body(S& b) { body = b; }
	auto get_recv() -> std::string const { return reciever; };
	auto get_sender() -> std::string const { return sender; };
	auto get_ts() -> std::string const { return timestamp; };
	auto get_body() -> std::string const { return body; };
	auto serialize_msg() -> const std::string;
	void set_ts(const char* t) { timestamp = t; };
	void set_message_id(const char* id) { message_id = id; };

private:
	//std::time_t timestamp{};
	std::string timestamp;
	std::string message_id;
	std::string sender;
	std::string reciever;
	std::string body;

};
