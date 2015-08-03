#sha256 - calculate SHA-256 message digest

[![Build Status](https://travis-ci.org/Thoronador/secure-hash-algorithm.svg)](https://travis-ci.org/Thoronador/secure-hash-algorithm)

##Purpose of the program

The sha256 program calculates and prints SHA-256 (256bit) checksums
of all files that are passed to it as command line parameters.
As of version 1.1 it can also be used to calculate SHA-1 (160bit)
checksums, if desired. Version 1.2 also offers SHA-224 (224bit checksum).

## Program call

Since this (obviously) is a command line program, you can call it
via command line/ shell. A list of valid options follows below.


### Synopsis

  sha256 [--sha1 | --sha224 | --sha256] FILENAME ...


### Options + parameters

  --sha1
      Calculate SHA-1 (160bit) checksums instead of SHA-256.

  --sha224
      Calculate SHA-224 (224bit) checksums instead of SHA-256.

  --sha256
      Calculate SHA-256 (256bit) checksums. This is the default.

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


##License, disclaimer and source code

The program sha256 is released under the GNU General Public License
version 3, a free software license. For the full text of the license
consult the file LICENSE or view it online at
  <http://www.gnu.org/licenses/gpl-3.0.html>

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN-
TABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
Public License for more details.

The program's source code is published at GitHub.com, the
project itself is located at
  <https://github.com/Thoronador/secure-hash-algorithm>
