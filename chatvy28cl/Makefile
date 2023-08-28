
ifeq ($(OS),Windows_NT)
SRC_CL = $(wildcard *.cpp) ..\\utils.cpp
chatvy28cl.exe: $(SRC_CL)
	g++ -o $@ $^ -lWs2_32 ; 
else
SRC_CL = $(wildcard *.cpp) ../utils.cpp
chatvy28cl.o: $(SRC_CL) 
	g++ -o chatvy28cl.o $(SRC_CL); 
endif
	
clean:
	rm -rf *.o *.a *.exe *.obj
