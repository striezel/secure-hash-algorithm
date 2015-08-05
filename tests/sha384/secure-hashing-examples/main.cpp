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
#include "../../../libthoro/hash/sha384/sha384.hpp"
#include "../../../libthoro/hash/sha384/BufferSource.hpp"
#include "../../../libthoro/hash/sha384/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA384.pdf>
  as linked on
  <http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing>.
*/

const std::vector<std::pair<std::string, std::string> > tests =
{
  {"abc",
   "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
  {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
   "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"}
};


int main()
{
  for (auto && i : tests)
  {
    //next statement contains a nasty typecast
    const SHA384::MessageDigest md_sha384 = SHA384::computeFromBuffer(
                reinterpret_cast<uint8_t*>(const_cast<char*>(i.first.c_str())),
                i.first.size()*8);
    std::cout << "Message:" << std::endl
              << i.first << std::endl
              << "Expected digest:   " << i.second << std::endl
              << "Calculated digest: " << md_sha384.toHexString() << std::endl;
    if (i.second != md_sha384.toHexString())
    {
      std::cout << "ERROR: Message digest is not as expected!" << std::endl;
      return 1;
    }
  } //for
  std::cout << "Passed test!" << std::endl;
  return 0;
}
