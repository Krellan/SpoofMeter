REM This batch file serves the same purpose as "configure" under Linux
REM Run it to build SpoofMeter from the Windows command line

REM There appears to be no "make clean" equivalent in CMake
REM Fortunately all build products are isolated into one subdirectory

RMDIR /S /Q build
MKDIR build

CD build

REM Run CMake to build SpoofMeter
REM Stop running the batch file if any step fails

cmake -S .. -B .
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
cmake --build . --verbose
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%
cmake --install . --verbose
IF %ERRORLEVEL% NEQ 0 EXIT /B %ERRORLEVEL%

CD ..

ECHO "The build of SpoofMeter has completed successfully!"
