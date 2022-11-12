# We might support earlier versions, too, but try to use a recent one.
cmake_minimum_required(VERSION 3.8)

project(sha256)

# Recurse into subdirectory for sha256 executable.
add_subdirectory (sha256)

# enable tests
enable_testing()
# Recurse into subdirectory for test cases.
add_subdirectory (tests)
