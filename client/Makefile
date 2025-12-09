CXX = g++
CXXFLAGS = -std=c++17 -pthread

all: Client

Client: Client.cpp Client.h
	$(CXX) $(CXXFLAGS) -o Client Client.cpp

clean:
	rm -f Client
