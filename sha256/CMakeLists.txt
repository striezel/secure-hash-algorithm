# We might support earlier versions, too, but try to use a recent version.
cmake_minimum_required (VERSION 3.8...3.31)

project(sha256)

set(sha256_sources
    ../libstriezel/common/StringUtils.cpp
    ../libstriezel/filesystem/file.cpp
    ../libstriezel/hash/sha1/FileSourceUtility.cpp
    ../libstriezel/hash/sha1/sha1.cpp
    ../libstriezel/hash/sha224/FileSourceUtility.cpp
    ../libstriezel/hash/sha224/sha224.cpp
    ../libstriezel/hash/sha256/sha256.cpp
    ../libstriezel/hash/sha256/FileSource.cpp
    ../libstriezel/hash/sha256/FileSourceUtility.cpp
    ../libstriezel/hash/sha256/MessageSource.cpp
    ../libstriezel/hash/sha384/FileSourceUtility.cpp
    ../libstriezel/hash/sha384/sha384.cpp
    ../libstriezel/hash/sha512/FileSource.cpp
    ../libstriezel/hash/sha512/FileSourceUtility.cpp
    ../libstriezel/hash/sha512/MessageSource.cpp
    ../libstriezel/hash/sha512/sha512.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -O3 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()

# enable C++11 support
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sha256 ${sha256_sources})
