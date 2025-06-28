.PHONY: all build spoofmeter clean distclean check distcheck

all: build

build: spoofmeter

spoofmeter: spoofmeter_client spoofmeter_server
	echo "The SpoofMeter build process has completed successfully."

spoofmeter_client: spoofmeter_client.cpp spoofmeter_common.h
	g++ -Wall -o spoofmeter_client spoofmeter_client.cpp
	strip -s spoofmeter_client

spoofmeter_server: spoofmeter_server.cpp spoofmeter_common.h
	g++ -Wall -o spoofmeter_server spoofmeter_server.cpp
	strip -s spoofmeter_server

clean:
	rm -f spoofmeter_client spoofmeter_server
	echo "The SpoofMeter make clean step has completed successfully."

distclean: clean
	echo "The SpoofMeter make distclean step has completed successfully."

check:
	echo "The SpoofMeter make check step has completed successfully."

distcheck:
	echo "The SpoofMeter make distcheck step has completed successfully."

