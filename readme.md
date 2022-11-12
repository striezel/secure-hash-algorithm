# sha256 - calculate SHA-256 message digest

[![GitHub GCC status](https://github.com/striezel/secure-hash-algorithm/workflows/GCC/badge.svg)](https://github.com/striezel/secure-hash-algorithm/actions)
[![GitHub Clang status](https://github.com/striezel/secure-hash-algorithm/workflows/Clang/badge.svg)](https://github.com/striezel/secure-hash-algorithm/actions)
[![GitHub MSYS2 status](https://github.com/striezel/secure-hash-algorithm/workflows/MSYS2/badge.svg)](https://github.com/striezel/secure-hash-algorithm/actions)
[![GitLab pipeline status](https://gitlab.com/striezel/secure-hash-algorithm/badges/master/pipeline.svg)](https://gitlab.com/striezel/secure-hash-algorithm/-/pipelines)

## Purpose of the program

The sha256 program calculates and prints SHA-256 (256bit) checksums
of all files that are passed to it as command line parameters.
It can also be used to calculate SHA-1 (160bit), SHA-224 (224bit),
SHA-384 (384bit) and SHA-512 (512bit) checksums, if desired.

## Program call

Since this (obviously) is a command line program, you can call it
via command line/ shell. A list of valid options follows below.


### Synopsis

  sha256 [--sha1 | --sha224 | --sha256 | --sha384 | --sha512] FILENAME ...


### Options + parameters

  --sha1
      Calculate SHA-1 (160bit) checksums instead of SHA-256.

  --sha224
      Calculate SHA-224 (224bit) checksums instead of SHA-256.

  --sha256
      Calculate SHA-256 (256bit) checksums. This is the default.

  --sha384
      Calculate SHA-384 (384bit) checksums instead of SHA-384.

  --sha512
      Calculate SHA-512 (512bit) checksums instead of SHA-256.

  --help
      Show a help message and list valid program options.

  --version
      Print version information and quit.

  FILENAME
        path to a file that should be hashed. Can be repeated
        multiple times.

A typical call could look like:

    sha256 foo.txt some_dir/bar.baz

This would calculate the SHA-256 message digests of foo.txt and
bar.baz in the subdirectory some_dir. If one of the given files does
not exist, the program quits.

## Building from source

### Prerequisites

To build sha256 from source you need a C++ compiler and CMake 2.8 or later.
It also helps to have Git, a distributed version control system, on your build
system to get the latest source code directly from the Git repository.

All three can usually be installed be typing

    apt-get install cmake g++ git

or

    yum install cmake gcc-c++ git

into a root terminal.

### Getting the source code

Get the source directly from Git by cloning the Git repository and change to
the directory after the repository is completely cloned:

    git clone https://gitlab.com/striezel/secure-hash-algorithm.git ./sha256
    cd sha256
    git submodule update --init --recursive

The last of the lines above initializes and updates the submodule that the
sha256 source code needs, too, to be build from source.

### Build process

The build process is relatively easy, because CMake does all the preparations.
Starting in the root directory of the source, you can do the following steps:

    mkdir build
    cd build
    cmake ../
    make sha256 -j2

Now the sha256 binary is built and ready for use.

## License, disclaimer and source code

Copyright 2015  Dirk Stolle

The program sha256 is released under the GNU General Public License
version 3, a free software license. For the full text of the license
consult the file LICENSE or view it online at
  <http://www.gnu.org/licenses/gpl-3.0.html>

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN-
TABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
Public License for more details.

The program's source code is published at GitLab.com, the
project itself is located at
  <https://gitlab.com/striezel/secure-hash-algorithm>
