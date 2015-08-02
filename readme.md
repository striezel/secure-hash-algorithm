#sha256 - calculate SHA-256 message digest

[![Build Status](https://travis-ci.org/Thoronador/secure-hash-algorithm.svg)](https://travis-ci.org/Thoronador/secure-hash-algorithm)

##Purpose of the programme

The sha256 programme calculates and prints SHA-256 (256bit) checksums
of all files that are passed to it as command line parameters.
As of version 1.1 it can also be used to calculate SHA-1 (160bit)
checksums, if desired.

## Programme call

Since this (obviously) is a command line programme, you can call it
via command line/ shell. A list of valid options follows below.


### Synopsis

  sha256 [--sha1 | --sha256] FILENAME ...


### Options + parameters

  --sha1
      Calculate SHA-1 (160bit) checksums instead of SHA-256.

  --sha256
      Calculate SHA-256 (256bit) checksums. This is the default.

  --help
      Show a help message and list valid programme options.

  --version
      Print version information and quit.

  FILENAME
        path to a file that should be hashed. Can be repeated
        multiple times.

A typical call could look like:

    sha256 foo.txt some_dir/bar.baz

This would calculate the SHA-256 message digests of foo.txt and
bar.baz in the subdirectory some_dir. If one of the given files does
not exist, the programme quits.


##Licence, disclaimer and source code

The programme sha256 is released under the GNU General Public Licence
version 3, a free software licence. For the full text of the licence
consult the file GPL.txt or view it online at
  <http://www.gnu.org/licenses/gpl-3.0.html>

This programme is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHAN-
TABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
Public License for more details.

The programme's source code is published at Sourceforge.net, the
project itself is located at
  <http://sourceforge.net/projects/random-thoro/>
