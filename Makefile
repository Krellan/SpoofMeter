.PHONY: all clean

all: spoofmeter

spoofmeter: spoofmeter_client spoofmeter_server

spoofmeter_client: spoofmeter_client.cpp spoofmeter_common.h
	g++ -Wall -o spoofmeter_client spoofmeter_client.cpp
	strip -s spoofmeter_client

spoofmeter_server: spoofmeter_server.cpp spoofmeter_common.h
	g++ -Wall -o spoofmeter_server spoofmeter_server.cpp
	strip -s spoofmeter_server

clean:
	rm -f spoofmeter_client spoofmeter_server

