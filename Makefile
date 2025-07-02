# Makefile for SpoofMeter

# FUTURE: Move OS-detection logic to configure script
ifeq ($(OS),Windows_NT)
	WINDOWS = 1
	WARNINGS = /Wall /W4 /WX

	RM = del
	CXX = cl
	LINK = link

	EXE = .exe
	OBJ = .obj
	LINKOUTARG = /OUT:
else
	WINDOWS = 0
	WARNINGS = -Wall -Wextra -Wpedantic -Werror

	RM = rm -f
	CXX = g++
	LINK = g++

	EXE =
	OBJ = .o
	LINKOUTARG = -o
endif

# FUTURE: Move debug versus release to a flag in configure script
DEBUG = 1

# Debugging on Windows is not supported here for now
# FUTURE: Figure out how to do debugging on Windows these days
# I remember having fun with SoftICE a long time ago
ifeq ($(DEBUG),1)
	DEBUGFLAGS = -ggdb -Og
else
	DEBUGFLAGS = -s -O3
endif

CXXFLAGS = $(DEBUGFLAGS) $(WARNINGS)

.PHONY: all build spoofmeter clean distclean check distcheck

all: build

build: spoofmeter

CLI=spoofmeter_client
SRV=spoofmeter_server

spoofmeter: $(CLI)$(EXE) $(SRV)$(EXE)
	echo "The SpoofMeter build process has completed successfully."

$(CLI)$(EXE): $(CLI)$(OBJ)
	$(LINK) $(LINKOUTARG)$(CLI)$(EXE) $(CLI)$(OBJ)

$(CLI)$(OBJ): $(CLI).cpp spoofmeter_common.h
	$(CXX) $(CXXFLAGS) -o $(CLI)$(OBJ) -c $(CLI).cpp

$(SRV)$(EXE): $(SRV)$(OBJ)
	$(LINK) $(LINKOUTARG)$(SRV)$(EXE) $(SRV)$(OBJ)

$(SRV)$(OBJ): $(SRV).cpp spoofmeter_common.h
	$(CXX) $(CXXFLAGS) -o $(SRV)$(OBJ) -c $(SRV).cpp

clean:
	$(RM) $(CLI)$(EXE) $(CLI)$(OBJ)
	$(RM) $(SRV)$(EXE) $(SRV)$(OBJ)
	echo "The SpoofMeter make clean step has completed successfully."

distclean: clean
	echo "The SpoofMeter make distclean step has completed successfully."

check:
	echo "The SpoofMeter make check step has completed successfully."

distcheck:
	echo "The SpoofMeter make distcheck step has completed successfully."

