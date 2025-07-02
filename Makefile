# This is the Makefile for Microsoft NMAKE on Windows
# Linux uses "GNUmakefile" instead

# Unfortunately, due to syntactic differences between Microsoft NMAKE and GNU Make,
# there is no way that I have found to do it all from within one file.

WINDOWS = 1
WARNINGFLAGS = /Wall /W4 /WX

RM = DEL
CC = CL
LINK = LINK

EXE = .exe
OBJ = .obj
CCONLYARG = /EHsc /c
CCOUTARG = /Fo:
LINKOUTARG = /OUT:

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
