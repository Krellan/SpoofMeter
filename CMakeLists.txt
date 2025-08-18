# SpoofMeter

# TODO: finish porting, from classic makefiles to CMake
# TODO: add DEBUG option, to influence the flags
# TODO: test on Windows also, make sure it also builds there

# Minimum version for working CMAKE_EXPORT_COMPILE_COMMANDS support
cmake_minimum_required(VERSION 3.18)

project(SpoofMeter)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(spoofmeter_client
    spoofmeter_client.cpp
)

add_executable(spoofmeter_server
    spoofmeter_server.cpp
)

add_library(spoofmeter_common STATIC
    spoofmeter_common.cpp
    spoofmeter_common.h
)

target_link_libraries(spoofmeter_client PUBLIC
    spoofmeter_common
)

target_link_libraries(spoofmeter_server PUBLIC
    spoofmeter_common
)
