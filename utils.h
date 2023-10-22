#pragma once
#include <stdio.h>
#include <iostream>
#include <vector>

#ifdef __linux__

#include <sys/utsname.h>  //for uname()

const std::string RESET{ "\033[0m" };
const std::string UNDER_LINE{ "\033[4m" };
const std::string BLACK{ "\033[30m" };
const std::string RED{ "\033[31m" };
const std::string GREEN{ "\033[32m" };
const std::string YELLOW{ "\033[33m" };
const std::string BLUE{ "\033[34m" };
const std::string MAGENTA{ "\033[35m" };
const std::string CYAN{ "\033[36m" };
const std::string WHITE{ "\033[37m" };

const std::string BOLDBLACK{ "\033[1m\033[30m" };
const std::string BOLDRED{ "\033[1m\033[31m" };
const std::string BOLDGREEN{ "\033[1m\033[32m" };
const std::string BOLDYELLOW{ "\033[1m\033[33m" };
const std::string BOLDBLUE{ "\033[1m\033[34m" };
const std::string BOLDMAGENTA{ "\033[1m\033[35m" };
const std::string BOLDCYAN{ "\033[1m\033[36m" };
const std::string BOLDWHITE{ "\033[1m\033[37m" };

#elif defined (_WIN32) || defined (_WIN64)
#include <windows.h>
#include <sysinfoapi.h>
#include <VersionHelpers.h>

const std::string RESET{ "\033[0m" };
const std::string UNDER_LINE{ "\033[4m" };
const std::string BLACK{ "\033[30m" };
const std::string RED{ "\033[31m" };
const std::string GREEN{ "\033[32m" };
const std::string YELLOW{ "\033[33m" };
const std::string BLUE{ "\033[34m" };
const std::string MAGENTA{ "\033[35m" };
const std::string CYAN{ "\033[36m" };
const std::string WHITE{ "\033[37m" };

const std::string BOLDBLACK{ "\033[1m\033[30m" };
const std::string BOLDRED{ "\033[1m\033[31m" };
const std::string BOLDGREEN{ "\033[1m\033[32m" };
const std::string BOLDYELLOW{ "\033[1m\033[33m" };
const std::string BOLDBLUE{ "\033[1m\033[34m" };
const std::string BOLDMAGENTA{ "\033[1m\033[35m" };
const std::string BOLDCYAN{ "\033[1m\033[36m" };
const std::string BOLDWHITE{ "\033[1m\033[37m" };

#endif


#define MAX_PWD_SZ 16
//-----------------------------------------------------------------------------------------
struct cHasher {
	std::size_t operator()(const std::string& uname) const noexcept {
		size_t sum{};
		for (const auto& c : uname)
			sum += static_cast<size_t>(c);
		return (sum % mem_size) << 1;// 
	}
	const size_t mem_size{ 64 };
};
//==============================================================================================
auto getPassword(std::string&) -> void;
auto print_os_data() -> void;
auto get_login_by_id_from_packed_string(const std::string& sid) -> const std::string;
auto split_msg_data(const std::string& r, std::vector<std::string>& v, const char* div="~")->bool;

