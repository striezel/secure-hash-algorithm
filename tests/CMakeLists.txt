# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required(VERSION 2.8)

# Recurse into subdirectory for SHA-1 test (160bit digest).
add_subdirectory (sha160)

# Recurse into subdirectory for SHA-256 test.
add_subdirectory (sha256)
