#include "utils.h"
#ifdef __linux__
#include <unistd.h>
#endif
//===================================================================================
auto getPassword(std::string& pwd) -> void {
    pwd.erase();
#if defined(_WIN32) || defined(_WIN64)
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    std::cin>>pwd;
    SetConsoleMode(hStdin, mode);
#elif defined(__linux__)
	pwd = std::string(getpass(pwd.c_str()));
#endif
	std::cout << RESET<<std::endl;
}
//------------------------------------------------------------------------------------
auto print_os_data() -> void {
#ifdef __linux__
    struct utsname utsname;
    uname(&utsname);
    printf("OS name: %s (%s:%s)\n", utsname.sysname, utsname.release, utsname.version);

#elif defined(_WIN32) || defined(_WIN64)
     auto sharedUserData = (BYTE*)0x7FFE0000;
    std::cout << BOLDCYAN << "OS name: Windows " << *(ULONG*)(sharedUserData + 0x26c)<<"."
                                                                    << *(ULONG*)(sharedUserData + 0x270)<<"."
                                                                    << *(ULONG*)(sharedUserData + 0x260)
                                                                    << RESET << std::endl;
#else
    printf("Failed to define current OS\n");
#endif
 
}
//------------------------------------------------------------------------------------
auto get_login_by_id_from_packed_string(const std::string& sid) -> const std::string {

    return "";


}
//------------------------------------------------------------------------------------




