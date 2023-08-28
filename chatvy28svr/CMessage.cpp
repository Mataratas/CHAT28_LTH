#include "CMessage.h"
//---------------------------------------------------------------------------------------------
CMessage::CMessage(const char* msg) {
	if (msg) {
		std::string s_tmp(msg);
		size_t pos = s_tmp.find('|');
		std::string arr_parts[5];
		size_t cnt{ 0 };

		while (pos != std::string::npos) {
			arr_parts[cnt++] = s_tmp.substr(0, pos);
			s_tmp.erase(0, pos + 1);
			pos = s_tmp.find('|');
		}
		arr_parts[cnt] = s_tmp;
		timestamp = arr_parts[0];//strtoul(arr_parts[0].c_str(), nullptr, 10);
		sender = arr_parts[1];
		reciever = arr_parts[2];
		body = arr_parts[3];
	}
}
//---------------------------------------------------------------------------------------------
auto CMessage::serialize_msg() -> const std::string {
	std::string res;
	res.reserve(1024);
	res += timestamp; res.push_back('#');
	res += body; res.push_back('#');
	res += sender; res.push_back('#');
	res += message_id; res.push_back('#');
	return res;
}
//---------------------------------------------------------------------------------------------
