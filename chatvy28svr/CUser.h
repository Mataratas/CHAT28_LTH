#pragma once
#include <iostream>
#include <string>
//========================================================================================
class CUser {
public:
	CUser() = delete;
	explicit CUser(const char*, const char*);
	CUser(const CUser&);
	~CUser() = default;
	CUser& operator=(const CUser&);
	template<class S> void set_name(const S& nm) { _name = nm; };
	template<class S> void set_pwd(const S& p) { _pwd_hash = p; };
	std::string get_name() const { return _name; };
	auto get_pwd_hash() -> std::string const { return _pwd_hash; };
	auto get_id() -> uint64_t const { return _id; };

	auto set_new_one(bool p) { _new_one = p; };
	auto set_id(uint64_t p) { _id = p; };
	bool operator==(const CUser& rhs);
	bool operator!=(const CUser& rhs);
	friend std::ostream& operator<<(std::ostream& out, const CUser&);
private:
	uint64_t _id;
	std::string _name;
	std::string _pwd_hash;
	bool _new_one{ false };
};
