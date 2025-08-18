# This is the Makefile for Microsoft NMAKE on Windows
# Linux uses "GNUmakefile" instead

# Unfortunately, due to syntactic differences between Microsoft NMAKE and GNU Make,
# there is no way that I have found to do it all from within one file.

WINDOWS = 1
WARNINGFLAGS = /Wall /W4
# Can't use /WX because Windows header files themselves have warnings

RM = DEL
CC = CL
LINK = LINK

EXE = .EXE
OBJ = .OBJ
CCONLYARG = /EHsc /c
CCOUTARG = /Fo:
LINKOUTARG = /OUT:
LINKLIBS = WS2_32.LIB IPHLPAPI.LIB

# FUTURE: Move debug versus release to a flag in configure script
DEBUG = 1

!IF $(DEBUG) == 1
DEBUGCCFLAGS = /Od /Zi
DEBUGLINKFLAGS = /DEBUG:FULL
!ELSE
DEBUGCCFLAGS = /O2
DEBUGLINKFLAGS =
!ENDIF

!INCLUDE spoofmeter.mk
