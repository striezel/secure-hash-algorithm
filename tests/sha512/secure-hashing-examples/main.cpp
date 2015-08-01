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
#include "../../../libthoro/hash/sha512/sha512.hpp"
#include "../../../libthoro/hash/sha512/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are taken from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA512.pdf>
  as linked on
  <http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing>.
*/

const std::vector<std::pair<std::string, std::string> > tests =
{
  {"abc",
   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
  {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
   "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"}
};


int main()
{
  for (auto && i : tests)
  {
    //next statement contains a nasty cast
    const SHA512::MessageDigest md_sha512 = SHA512::computeFromBuffer(
                reinterpret_cast<uint8_t*>(const_cast<char*>(i.first.c_str())),
                i.first.size()*8);
    std::cout << "Message:" << std::endl
              << i.first << std::endl
              << "Expected digest:   " << i.second << std::endl
              << "Calculated digest: " << md_sha512.toHexString() << std::endl;
    if (i.second != md_sha512.toHexString())
    {
      std::cout << "ERROR: Message digest is not as expected!" << std::endl;
      return 1;
    }
  } //for
  std::cout << "Passed test!" << std::endl;
  return 0;
}
