
ifeq ($(OS), Windows_NT)
SQL_HEAD_DIR = "C:\Program Files\MySQL\MySQLServer8\include"
SQL_LIB_DIR = "C:\Program Files\MySQL\MySQLServer8\lib"
SRC_SVR = $(wildcard *.cpp) ..\\utils.cpp
HEADERS = $(SQL_HEAD_DIR)

chatvy28srv.exe: $(SRC_SVR) 
	g++  -I$(HEADERS) -L$(SQL_LIB_DIR) -std=c++17 -o $@ $^ -lWs2_32  -lmysql -lpthread
else
SRC_SVR = main.cpp CUser.cpp CTCPServer.cpp CMessage.cpp CDBAccess.cpp ../utils.cpp
chatvy28srv.o: $(SRC_SVR) 
HEADERS =  /usr/include/mysql/
LIBS = /usr/lib/x86_64-linux-gnu
chatvy28srv.o: $(SRC_SVR) 
	g++ -I$(HEADERS) -L$(LIBS) -o $@ $^ -lmysqlpp -lmysqlclient -lpthread -ldl -lssl -lcrypto -lresolv -lm -lrt
endif

clean:
	rm -rf *.o *.a *.exe *.obj

	