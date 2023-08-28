#include "CUser.h"
#pragma warning(disable : 4996)
//========================================================================================
CUser::CUser(const char* nm, const char* pwdh):_name(nm), _pwd_hash(pwdh){

	//std::cout<<"CUser constructor: name = "<<name<<std::endl;	
}
//---------------------------------------------------------------------------------------
CUser::CUser(const CUser& rhs){
	_name = rhs._name;
	_pwd_hash == rhs._pwd_hash;
}
//---------------------------------------------------------------------------------------
CUser& CUser::operator=(const CUser& rhs){
	if(*this==rhs)
		return *this;
	_name = rhs._name;
	_pwd_hash == rhs._pwd_hash;
	return *this;
}
//---------------------------------------------------------------------------------------
bool CUser::operator==(const CUser& rhs) {
	return _name == rhs.get_name() && _pwd_hash==rhs._pwd_hash;
}
//---------------------------------------------------------------------------------------
bool CUser::operator!=(const CUser& rhs) {
	return _name != rhs.get_name();
}
//---------------------------------------------------------------------------------------
std::ostream& operator<<(std::ostream& out, const CUser& usr) {
	out << "Name:" << usr._name << " Pwd hash:" << usr._pwd_hash << std::endl;
	return out;
}
//---------------------------------------------------------------------------------------

