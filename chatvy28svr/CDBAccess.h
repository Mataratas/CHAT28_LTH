#pragma once
#include <iostream>
#include <memory>
//#pragma comment(lib,"libmysql.lib")

#ifdef __linux__
#include <mysql/mysql.h>
#elif defined(_WIN64) || defined(_WIN32)
#include <windows.h>
#include <iomanip>
#include <string>
#include <sal.h>
#include <tchar.h>
#include <mysql.h>
#endif

#include <vector>
#include <map>
#include <unordered_map>

#include "CMessage.h"
#include "CUser.h"
#include "ÑLogger.h"

#include "../utils.h"

enum DatabaseRetCodes {
    eUnableToAllocateEnv,
    eUnableToAllocateConnection,
    eUnableToAllocateQuery,
    eFailedToConnectToServer,
    eFailedToConnectToDatabase,
    eUnableToDefineODBCversion,
    eFailedToExecuteQuery,
    eFailedToCreateDatabase,
    eFailedToCreateTable,
    eFailedToCreateTrigger,
    eDatabaseAlreadyExists,
    eDatabaseCreatedOK,
    eInsertFailed,
    eInsertOK,
    eUpdateFailed,
    eUpdateOK,
    eDeleteFailed,
    eDeleteOK,
    eRecordExists,
    eRecordNotFound
};
using DRC = DatabaseRetCodes;

constexpr auto SQL_RESULT_LEN = 240;
constexpr auto SQL_QUERY_SIZE = 1024;

//=====================================================================================================================
class CDBAccess{
public:
    CDBAccess();
    ~CDBAccess();
    CDBAccess(const CDBAccess&) = delete;
    CDBAccess& operator=(const CDBAccess&)=delete;
    auto show_version(void) -> void;
    template<typename S> auto set_uid(const S& s)-> void { _UID = s;};
    template<typename S> auto set_pwd(const S& s)-> void { _PWD = s; };
    template<typename S> auto set_db_name(const S& s) -> void { _dbname = s; };
    template<typename S> auto set_server(const S& s) -> void { _server = s; };
    template<typename S> auto set_odbc_port(const S& s) -> void { _odbc_port = s; };
    auto set_mysql_port(unsigned int p)->void { _mysql_port = p; };


    auto init_ok()-> bool;
    auto get_last_error() -> const char* const { return _last_error.c_str();};
    auto add_user(const char *l, uint64_t&, const char *n=nullptr, const char *e=nullptr)-> bool;
    auto get_user(const char* , uint64_t&, std::string&, std::string&, std::string&) -> bool;
    auto get_user_msgs(const uint64_t&, const std::string&, std::map<std::string, std::shared_ptr<CMessage>>&)->void;

    auto read_users(std::unordered_map<size_t, std::shared_ptr<CUser>>&)->void;
    auto pack_users(const char* client_id, std::string& ) -> bool const;
    auto write_users(const std::unordered_map<size_t, std::shared_ptr<CUser>>&) -> void;


    auto user_pwdh_ok(const char*, const std::string&) -> bool;
    auto user_pwdh_ok(const uint64_t&, const std::string&) -> bool;

    auto login_used(const char*) -> bool;
    auto set_user_attr(const uint64_t&, const char*, const char*) -> bool;
    auto set_msg_state(const char*, const char*) -> bool;
    auto set_user_pwdhash(const uint64_t&, const char*) -> bool;

    //auto deliver_msg(const std::shared_ptr<CMessage> &msg, const uint64_t& from_id, const uint64_t& to_id=0)->size_t;
    auto deliver_msg(const char* msg, const char* from_id, const char* to_id = nullptr) -> bool;


private:
    auto _init_db_ctx()-> DRC;
    auto _database_ready() -> DRC;
    auto _db_success(DRC) -> bool;
    auto _query_exec(const std::string& ,uint64_t* id = nullptr) -> bool;

    MYSQL *_mysql{nullptr};
    std::string _server{"localhost"};
    std::string _odbc_port{"3306"};
    unsigned int _mysql_port{0};
    std::string _dbname{"chatvy28"};
    std::string _UID{"root"};
    std::string _PWD{"1234"};
    std::string _last_error;
    DRC _last_ret_code;

};
using DBCTX = CDBAccess;
