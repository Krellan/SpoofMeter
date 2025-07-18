# Makefile for SpoofMeter

# This is the second half of the Makefile,
# and is common to both Linux and Windows builds.
# All the OS-specific stuff should have been ran first,
# from Makefile (for Windows) or GNUmakefile (for Linux).

CCFLAGS = $(DEBUGCCFLAGS) $(WARNINGFLAGS)
LINKFLAGS = $(DEBUGLINKFLAGS)

# Simply to save a lot of typing
CLI = spoofmeter_client
SRV = spoofmeter_server

all: build
	echo "The SpoofMeter make process has completed successfully."

build: spoofmeter
	echo "The SpoofMeter build process has completed successfully."

spoofmeter: $(CLI)$(EXE) $(SRV)$(EXE)
	echo "The SpoofMeter executables have been built successfully."

$(CLI)$(EXE): $(CLI)$(OBJ)
	$(LINK) $(LINKFLAGS) $(CLI)$(OBJ) $(LINKOUTARG)$(CLI)$(EXE)

$(CLI)$(OBJ): $(CLI).cpp spoofmeter_common.h
	$(CC) $(CCFLAGS) $(CCONLYARG) $(CLI).cpp $(CCOUTARG)$(CLI)$(OBJ)

$(SRV)$(EXE): $(SRV)$(OBJ)
	$(LINK) $(LINKFLAGS) $(SRV)$(OBJ) $(LINKOUTARG)$(SRV)$(EXE)

$(SRV)$(OBJ): $(SRV).cpp spoofmeter_common.h
	$(CC) $(CCFLAGS) $(CCONLYARG) $(SRV).cpp $(CCOUTARG)$(SRV)$(OBJ)

# The "-" is necessary because Microsoft DEL has no equivalent to -f ignore errors
clean:
	-$(RM) $(CLI)$(EXE)
	-$(RM) $(CLI)$(OBJ)
	-$(RM) $(SRV)$(EXE)
	-$(RM) $(SRV)$(OBJ)
	-$(RM) $(CLI).ilk
	-$(RM) $(SRV).ilk
	-$(RM) $(CLI).pdb
	-$(RM) $(SRV).pdb
	-$(RM) vc140.pdb
	echo "The SpoofMeter make clean step has completed successfully."

distclean: clean
	echo "The SpoofMeter make distclean step has completed successfully."

check:
	echo "The SpoofMeter make check step has completed successfully."

distcheck:
	echo "The SpoofMeter make distcheck step has completed successfully."

