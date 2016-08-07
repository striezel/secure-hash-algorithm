# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(sha256)

# enable C++11 support
add_definitions(-std=c++0x)

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

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O3 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(sha256 ${sha256_sources})
