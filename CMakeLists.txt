# SpoofMeter

# TODO: finish porting, from classic makefiles to CMake
# TODO: add DEBUG option, to influence the flags
# TODO: test on Windows also, make sure it also builds there

# Matches Ubuntu 24 as seen within WSL in Windows 11
# https://cliutils.gitlab.io/modern-cmake/chapters/intro/dodonot.html
cmake_minimum_required(VERSION 3.28)

project(SpoofMeter
        VERSION 1.0
        DESCRIPTION "SpoofMeter client and server"
        LANGUAGES CXX
)

# Set only if the default has not already been established somewhere else
# https://cliutils.gitlab.io/modern-cmake/chapters/features/cpp11.html
set(CMAKE_CXX_STANDARD 11 CACHE STRING "The C++ standard to use")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# https://clang.llvm.org/docs/JSONCompilationDatabase.html
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# TODO: Change default to OFF here when reasonably complete
option(DEBUG
        "Build mode, ON for debug, OFF for release"
        ON
)

if(DEBUG)
        message(STATUS "Building in Debug mode")

        set(CMAKE_BUILD_TYPE Debug)

        # Avoid future breakage by not also enabling this for release
        # https://stackoverflow.com/questions/73215417/treat-compiler-warnings-as-errors
        set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

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
else()
        message(STATUS "Building in Release mode")
        
        set(CMAKE_BUILD_TYPE Release)

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
endif()

# TODO: also support the Mac
if (MSVC)
        message(STATUS "Building with Windows compiler")
        
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
        message(STATUS "Building with GNU compiler")
        
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
)

add_executable(spoofmeter_server
        spoofmeter_server.cpp
        spoofmeter_common.h
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

