cmake_minimum_required(VERSION 3.16)

project(tui-packet-inspector
    VERSION 1.0.0
    DESCRIPTION "Zero-dependency terminal packet inspector for TCP, UDP and Modbus"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(TPI_BUILD_TESTS "Build the unit test suite" ON)
option(TPI_ENABLE_SANITIZERS "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

find_package(Threads REQUIRED)

# --- shared compiler settings ------------------------------------------------
add_library(tpi_options INTERFACE)
if(MSVC)
    target_compile_options(tpi_options INTERFACE /W4 /permissive- /utf-8)
    target_compile_definitions(tpi_options INTERFACE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(tpi_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
    if(TPI_ENABLE_SANITIZERS)
        target_compile_options(tpi_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(tpi_options INTERFACE -fsanitize=address,undefined)
    endif()
endif()

# --- core library: capture engine, protocol decoders, statistics, TUI ------------
add_library(tpi_core STATIC
    src/PacketBuffer.cpp
    src/NetworkSniffer.cpp
    src/PcapFile.cpp
    src/SyntheticSource.cpp
    src/ProtocolDecoder.cpp
    src/TrafficStats.cpp
    src/Terminal.cpp
    src/TuiRenderer.cpp)

target_include_directories(tpi_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(tpi_core PUBLIC cxx_std_17)
target_compile_definitions(tpi_core PUBLIC TPI_VERSION="${PROJECT_VERSION}")
target_link_libraries(tpi_core PUBLIC Threads::Threads PRIVATE tpi_options)

if(WIN32)
    target_compile_definitions(tpi_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0601)
    target_link_libraries(tpi_core PUBLIC ws2_32)
endif()

# --- executable ----------------------------------------------------------------
add_executable(tui-packet-inspector src/main.cpp)
target_link_libraries(tui-packet-inspector PRIVATE tpi_core tpi_options)

if(MINGW)
    # Ship a self-contained binary that runs outside the MinGW shell.
    target_link_options(tui-packet-inspector PRIVATE -static)
endif()

install(TARGETS tui-packet-inspector RUNTIME DESTINATION bin)

# --- tests ---------------------------------------------------------------------
if(TPI_BUILD_TESTS)
    enable_testing()
    add_executable(tpi_tests
        tests/TestMain.cpp
        tests/CaptureTests.cpp
        tests/DecoderTests.cpp
        tests/DashboardTests.cpp)
    target_link_libraries(tpi_tests PRIVATE tpi_core tpi_options)
    if(MINGW)
        target_link_options(tpi_tests PRIVATE -static)
    endif()
    add_test(NAME tpi_tests COMMAND tpi_tests)
endif()
