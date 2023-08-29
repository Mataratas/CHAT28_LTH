#include "CLogger.h"
#include<iostream>
//================================================================================
CLogger::CLogger(const char* prefix) :_log_pref(prefix){
	_file.open(_get_file_name().c_str(), std::ios::in | std::ios::app); //r+
	if (!_file)
		_init_ok = false;

	_init_ok = true;
#ifdef _DEBUG
	std::cout << __FUNCTION__ << ": initialization " << (_init_ok ? "OK" : "FAILED") << std::endl;
#endif // _DEBUG
}
//---------------------------------------------------------------------------------
CLogger::~CLogger() {
	if (_init_ok && _file.is_open())
		_file.close();
}
//---------------------------------------------------------------------------------
auto CLogger::_get_file_name() -> const std::string {
	std::string fname{ _log_pref };
	fname += '_'; fname += _log_fn;
	return fname;
}
//---------------------------------------------------------------------------------
auto CLogger::read_line(std::string& l, int idx) -> bool {
	l.clear();
	_mtxs.lock_shared();
	if (!_file.is_open())
		_file.open(_get_file_name().c_str(), std::ios::in | std::ios::app);

	if (_file.is_open()) {
		_file.seekg(0, std::ios_base::end);
		if (static_cast<int>(_file.tellg()) <= 0)
			return false; //file is empty

		if (idx == -1) {
			_file.seekg(-3, std::ios_base::end);
			while (true) {
				char ch;
				_file.get(ch);
				l.insert(0, 1, ch);
				if (ch == '[') {
					break;
				}
				else
					_file.seekg(-2, std::ios_base::cur);
			}
		}
		else if (idx == 0) {
			_file.seekg(0, std::ios_base::beg);
			char mbstr[MAX_LOG_LINE_LEN]{ '\0' };
			_file.getline(mbstr, MAX_LOG_LINE_LEN);
			l = mbstr;
		}
		else
			std::cout << "Not yet implemented\n";
	}
	_mtxs.unlock_shared();
	return l.size() > 0;
}
//---------------------------------------------------------------------------------
auto CLogger::write(const char* line) -> bool {
	if (!_init_ok) return false;
	_mtxs.lock();

	if(!_file.is_open())
		_file.open(_get_file_name().c_str(), std::ios::in | std::ios::app);


	auto now = std::chrono::system_clock::now();
	auto ts = std::chrono::system_clock::to_time_t(now);

	char mbstr[20]{'\0'};
#if defined(_WIN64) || defined(_WIN32)	
#pragma warning(suppress : 4996)
	if (std::strftime(mbstr, sizeof(mbstr), "%d.%m.%Y %H:%M:%S", std::localtime(&ts)))
#elif defined(__linux__)
	if (std::strftime(mbstr, sizeof(mbstr), "%d.%m.%Y %H:%M:%S", std::localtime(&ts)))
#endif
		_file <<"["<< mbstr << "] ";
	else
		_file << "[No timestamp      ] ";

	_file << line << std::endl;
	_file.close();
	_mtxs.unlock();
	return true;
}
//---------------------------------------------------------------------------------