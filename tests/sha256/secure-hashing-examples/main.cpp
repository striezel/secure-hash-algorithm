/*
 -----------------------------------------------------------------------------
    This file is part of a test suite for a secure hashing algorithm program.
    Copyright (C) 2015  Dirk Stolle

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
#include "../../../libthoro/hash/sha256/sha256.hpp"
#include "../../../libthoro/hash/sha256/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf>
  as linked on
  <http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing>.
*/

const std::vector<std::pair<std::string, std::string> > tests =
{
  {"abc",
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
  {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}
};


int main()
{
  for (auto && i : tests)
  {
    //next statement contains a nasty typecast
    const SHA256::MessageDigest md_sha256 = SHA256::computeFromBuffer(
                reinterpret_cast<uint8_t*>(const_cast<char*>(i.first.c_str())),
                i.first.size()*8);
    std::cout << "Message:" << std::endl
              << i.first << std::endl
              << "Expected digest:   " << i.second << std::endl
              << "Calculated digest: " << md_sha256.toHexString() << std::endl;
    if (i.second != md_sha256.toHexString())
    {
      std::cout << "ERROR: Message digest is not as expected!" << std::endl;
      return 1;
    }
  } //for
  std::cout << "Passed test!" << std::endl;
  return 0;
}
