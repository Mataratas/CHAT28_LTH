#include "CMessage.h"
#include<vector>
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
		timestamp = strtoul(arr_parts[0].c_str(), nullptr, 10);
		sender = arr_parts[1];
		reciever = arr_parts[2];
		body = arr_parts[3];
		type = std::stoi(s_tmp) == 1 ? eOld : eNew;
	}
}
//---------------------------------------------------------------------------------------------
auto CMessage::show_unpacked(const char* msg,std::string& message_id) -> void {
	std::string tmp{ msg };
	std::vector<std::string> v;
	auto div_pos = tmp.find("#");
	while (div_pos != std::string::npos) {
		v.push_back(tmp.substr(0, div_pos));
		tmp = tmp.substr(div_pos + 1);
		div_pos = tmp.find("#");
	}

	if (v.size()) {
		std::cout <<"\t\t----------------------------------------------------------------\n";
		std::cout << "\t\tDate [" << v[0] << "]" << " From:" << v[2] << std::endl;
		std::cout << "\t\t----------------------------------------------------------------\n";
		std::cout << "\t\tMessage:\n\t\t" << v[1] << std::endl;
		message_id = v[3];
	}
}
//---------------------------------------------------------------------------------------------
void CMessage::set_recv(const std::string& usr) {
	reciever = usr;
}
//---------------------------------------------------------------------------------------------
void CMessage::set_sender(const std::string& usr) {
	sender = usr;
}
//---------------------------------------------------------------------------------------------
void CMessage::set_msg_read() {
	type = eOld;
}
