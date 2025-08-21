# SpoofMeter

# Matches Ubuntu 24 as seen within WSL in Windows 11
# https://cliutils.gitlab.io/modern-cmake/chapters/intro/dodonot.html
cmake_minimum_required(VERSION 3.28)

project(SpoofMeter
        VERSION 1.0
        DESCRIPTION "SpoofMeter client and server"
        LANGUAGES CXX
)

message(STATUS "SpoofMeter now building!")

# Set only if the default has not already been established somewhere else
# https://cliutils.gitlab.io/modern-cmake/chapters/features/cpp11.html
set(CMAKE_CXX_STANDARD 11 CACHE STRING "The C++ standard to use")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# https://clang.llvm.org/docs/JSONCompilationDatabase.html
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

message(STATUS "Your CMAKE_CONFIGURATION_TYPES: ${CMAKE_CONFIGURATION_TYPES}")
message(STATUS "Your CMAKE_BUILD_TYPE (one of): ${CMAKE_BUILD_TYPE}")

# Visual Studio sets a different variable instead of CMAKE_BUILD_TYPE
# It sets CMAKE_CONFIGURATION_TYPES but with only one entry in this list
# So, take the first configuration and use that as the build type
if((NOT DEFINED CMAKE_BUILD_TYPE) OR ("${CMAKE_BUILD_TYPE}" STREQUAL ""))
    # Must test defined first to avoid empty string comparison gotcha
    if((DEFINED CMAKE_CONFIGURATION_TYPES) AND (NOT "${CMAKE_CONFIGURATION_TYPES}" STREQUAL ""))
        # Take first entry from list and use it as a string
        list(GET CMAKE_CONFIGURATION_TYPES 0 FIRST_ENTRY)
        set(CMAKE_BUILD_TYPE "${FIRST_ENTRY}")
    endif()
endif()

# Default to Debug if still nothing was specified
if((NOT DEFINED CMAKE_BUILD_TYPE) OR ("${CMAKE_BUILD_TYPE}" STREQUAL ""))
        set(CMAKE_BUILD_TYPE "Debug")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
        message(STATUS "Detected build type will be Debug")

        # Avoid future breakage by not also enabling this for release
        # https://stackoverflow.com/questions/73215417/treat-compiler-warnings-as-errors
        set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

        # TODO: would be nice to support split debugging on Linux
        set (DEBUG_GNU_CC_FLAGS
                "-Og"
                "-ggdb"
        )
        set (DEBUG_GNU_LD_FLAGS
        )

        set (DEBUG_WIN_CC_FLAGS
                "/Od"
                "/Zi"
        )
        set (DEBUG_WIN_LD_FLAGS
                "/DEBUG:FULL"
        )
elseif(("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    OR ("${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo"))
        message(STATUS "Detected build type will be Release")
        
        set (DEBUG_GNU_CC_FLAGS
                "-O3"
        )
        set (DEBUG_GNU_LD_FLAGS
                "-s"
        )
        
        set (DEBUG_WIN_CC_FLAGS
                "/O2"
        )
        set (DEBUG_WIN_LD_FLAGS
        )
else()
        message(STATUS "Detected CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} unsupported setting!")
endif()

# TODO: also test on the Mac and see what its native compiler needs
if (MSVC)
        message(STATUS "Detected building with the Windows toolchain")
        
        set(DEBUG_CC_FLAGS ${DEBUG_WIN_CC_FLAGS})
        set(DEBUG_LD_FLAGS ${DEBUG_WIN_LD_FLAGS})

        # No /WX here, set by CMAKE_COMPILE_WARNING_AS_ERROR
        set(WARNING_FLAGS
                "/Wall"
                "/W4"
        )

        set(MORE_CC_FLAGS
                "/EHsc"
        )

        set(EXTRA_LINK_LIBRARIES
                "ws2_32.lib"
                "iphlpapi.lib"
        )
else()
        message(STATUS "Detected building with the GNU toolchain")
        
        set(DEBUG_CC_FLAGS ${DEBUG_GNU_CC_FLAGS})
        set(DEBUG_LD_FLAGS ${DEBUG_GNU_LD_FLAGS})

        # No -Werror here, set by CMAKE_COMPILE_WARNING_AS_ERROR
        set(WARNING_FLAGS
                "-Wall"
                "-Wextra"
                "-Wpedantic"
        )

        set(MORE_CC_FLAGS
        )

        set(EXTRA_LINK_LIBRARIES
        )
endif()

# Put the pieces together
set(EXTRA_CC_FLAGS
        ${DEBUG_CC_FLAGS}
        ${WARNING_FLAGS}
        ${MORE_CC_FLAGS}
)
set(EXTRA_LD_FLAGS
        ${DEBUG_LD_FLAGS}
)

add_library(spoofmeter_common_lib STATIC
        spoofmeter_common.cpp
        spoofmeter_common.h
        socket_helper.cpp
        socket_helper.h
        packet_builder.cpp
        packet_builder.h
)

target_compile_options(spoofmeter_common_lib PRIVATE
        ${EXTRA_CC_FLAGS}
)
target_link_options(spoofmeter_common_lib PRIVATE
        ${EXTRA_LD_FLAGS}
)
target_link_libraries(spoofmeter_common_lib PRIVATE
        ${EXTRA_LINK_LIBRARIES}
)

add_executable(spoofmeter_client
        spoofmeter_client.cpp
        spoofmeter_common.h
        socket_helper.h
        packet_builder.h
)

target_compile_options(spoofmeter_client PRIVATE
        ${EXTRA_CC_FLAGS}
)
target_link_options(spoofmeter_client PRIVATE
        ${EXTRA_LD_FLAGS}
)
target_link_libraries(spoofmeter_client PRIVATE
        ${EXTRA_LINK_LIBRARIES}
        spoofmeter_common_lib
)

add_executable(spoofmeter_server
        spoofmeter_server.cpp
        spoofmeter_common.h
        socket_helper.h
        packet_builder.h
)

target_compile_options(spoofmeter_server PRIVATE
        ${EXTRA_CC_FLAGS}
)
target_link_options(spoofmeter_server PRIVATE
        ${EXTRA_LD_FLAGS}
)
target_link_libraries(spoofmeter_server PRIVATE
        ${EXTRA_LINK_LIBRARIES}
        spoofmeter_common_lib
)

message(STATUS "SpoofMeter now done with CMakeLists file!")
