# This is the Makefile for GNU Make on Linux
# Microsoft NMAKE on Windows uses "Makefile" instead

WINDOWS = 0
WARNINGFLAGS = -Wall -Wextra -Wpedantic -Werror

RM = rm -f
CC = g++
LINK = g++

EMPTY =
SPACE = $(EMPTY) $(EMPTY)

EXE =
OBJ = .o
CCONLYARG = -c
CCOUTARG = -o$(SPACE)
LINKOUTARG = -o$(SPACE)

# FUTURE: Move debug versus release to a flag in configure script
DEBUG = 1

ifeq ($(DEBUG),1)
	DEBUGCCFLAGS = -Og -ggdb
	DEBUGLINKFLAGS =
else
	DEBUGCCFLAGS = -O3
	DEBUGLINKFLAGS = -s
endif

include spoofmeter.mk
