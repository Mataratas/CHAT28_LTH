#pragma once
#include<thread>
#include<shared_mutex>
#include <fstream>
#include<string>
#include<ctime>

#define MAX_LOG_LINE_LEN 512
//================================================================================================
class CLogger{
public:
	CLogger(const char* prefix);
	~CLogger();
	CLogger(const CLogger&) = delete;
	CLogger& operator=(const CLogger&) = delete;
	auto write(const char*) -> bool;
	auto read_line(std::string& l,int idx=-1)->bool; //idx:	-1 -> read last line, 0 -> first line

private:
	const char* _log_fn{ "log.txt" };
	const char* _log_pref{ "" };
	auto _get_file_name()-> const std::string;
	std::fstream _file;
	std::shared_mutex _mtxs;
	bool _init_ok{ false };

};
//---------------------------------------------------------------------------------------------------
using LOG = CLogger;
