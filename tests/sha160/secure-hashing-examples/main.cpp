/*
 -----------------------------------------------------------------------------
    This file is part of a test suite for a secure hashing algorithm program.
    Copyright (C) 2015  Thoronador

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -----------------------------------------------------------------------------
*/

#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include "../../../libthoro/hash/sha1/sha1.hpp"
#include "../../../libthoro/hash/sha1/BufferSource.hpp"
#include "../../../libthoro/hash/sha1/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA1.pdf>
  as linked on
  <http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing>.
*/

const std::vector<std::pair<std::string, std::string> > tests =
{
  {"abc",
   "a9993e364706816aba3e25717850c26c9cd0d89d"},
  {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
   "84983e441c3bd26ebaae4aa1f95129e5e54670f1"}
};


int main()
{
  for (auto && i : tests)
  {
    //next statement contains a nasty typecast
    const SHA1::MessageDigest md_sha1 = SHA1::computeFromBuffer(
                reinterpret_cast<uint8_t*>(const_cast<char*>(i.first.c_str())),
                i.first.size()*8);
    std::cout << "Message:" << std::endl
              << i.first << std::endl
              << "Expected digest:   " << i.second << std::endl
              << "Calculated digest: " << md_sha1.toHexString() << std::endl;
    if (i.second != md_sha1.toHexString())
    {
      std::cout << "ERROR: Message digest is not as expected!" << std::endl;
      return 1;
    }
  } //for
  std::cout << "Passed test!" << std::endl;
  return 0;
}
