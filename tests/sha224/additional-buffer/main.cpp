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

#include <cstring>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include "../../../libthoro/hash/sha224/sha224.hpp"
#include "../../../libthoro/hash/sha224/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf>.
*/

const std::vector<std::tuple<std::size_t, char, std::string> > testData =
{
    // #1
    std::tuple<std::size_t, char, std::string>(1, 0xff,
        "e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5"),
    // #2 is implemented below
    // #3
    std::tuple<std::size_t, char, std::string>(56, '\0',
        "5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804"),
    // #4
    std::tuple<std::size_t, char, std::string>(1000, 0x51, /* Q */
        "3706197f66890a41779dc8791670522e136fafa24874685715bd0a8a"),
    // #5
    std::tuple<std::size_t, char, std::string>(1000, 0x41, /* A */
        "a8d0c66b5c6fdfd836eb3c6d04d32dfe66c3b1f168b488bf4c9c66ce"),
    // #6
    std::tuple<std::size_t, char, std::string>(1005, 0x99,
        "cb00ecd03788bf6c0908401e0eb053ac61f35e7e20a2cfd7bd96d640"),
    // #7
    std::tuple<std::size_t, char, std::string>(1000000, '\0',
        "3a5d74b68f14f3a4b2be9289b8d370672d0b3d2f53bc303c59032df3"),
    // #8
    std::tuple<std::size_t, char, std::string>(536870912, 0x41 /* A */,
        "c4250083cf8230bf21065b3014baaaf9f76fecefc21f91cf237dedc9"),
    // #9
    std::tuple<std::size_t, char, std::string>(1090519040, '\0',
        "014674abc5cb980199935695af22fab683748f4261d4c6492b77c543"),
    // #10
    std::tuple<std::size_t, char, std::string>(1610612799, 0x84,
        "a654b50b767a8323c5b519f467d8669837142881dc7ad368a7d5ef8f")
};

// maximum file size for "short" file tests
const std::size_t cShortMaximum = 1024*1024;

int main(int argc, char** argv)
{
  //switch for hashing longer messages (default: false)
  bool hashLongData = false;

  if (argc>1)
  {
    if (argv!=nullptr)
    {
      //first parameter: allow long messages
      if (argv[1] != nullptr)
      {
        const std::string param(argv[1]);
        if (param=="--long" || param=="-l")
        {
          hashLongData = true;
        } //if
        else
        {
          std::cout << "Error: Invalid parameter " << param << "!" << std::endl;
          return 1;
        }
      } //if argv[1] exists
    } //if argv != null
  } //if args are present

  if (!hashLongData)
  {
    std::cout << "Info: Skipping test data with messages longer than "
              << cShortMaximum << " bytes." << std::endl;
  }
  else
  {
    std::cout << "Info: Processing test data with messages longer than "
              << cShortMaximum << " bytes, too." << std::endl;
  }

  //create buffer for tests
  uint8_t * buffer = nullptr;
  buffer = new uint8_t[4];
  #if BYTE_ORDER == LITTLE_ENDIAN
  const uint32_t cSource4Bytes = 0x2499e0e5;
  #else
  const uint32_t cSource4Bytes = 0xe5e09924;
  #endif
  memcpy(buffer, &cSource4Bytes, 4);

  //hash second file
  SHA224::MessageDigest md_sha224 = SHA224::computeFromBuffer(buffer, 32);
  delete[] buffer;
  buffer = nullptr;
  std::cout << "Buffer: 4 bytes: 0xe5e09924" << std::endl
            << "Expected digest:   fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d" << std::endl
            << "Calculated digest: " << md_sha224.toHexString() << std::endl;
  if ("fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d" != md_sha224.toHexString())
  {
    std::cout << "ERROR: Message digest is not as expected!" << std::endl;
    return 1;
  }



  for (auto && item : testData)
  {
    if (hashLongData || (std::get<0>(item)<= cShortMaximum))
    {
      //generate buffer from data
      try
      {
        buffer = new uint8_t[std::get<0>(item)];
      }
      catch (...)
      {
        std::cout << "Error: Failed to allocate buffer of " << std::get<0>(item)
                  << " bytes!" << std::endl;
        return 1;
      } //try-catch
      memset(buffer, std::get<1>(item), std::get<0>(item));

      //reset hash
      md_sha224.setToNull();
      md_sha224 = SHA224::computeFromBuffer(buffer, std::get<0>(item)*8);
      delete[] buffer;
      buffer = nullptr;
      std::cout << "Message: "<< std::get<0>(item) << " bytes of " << static_cast<unsigned int>(std::get<1>(item)) << std::endl
                << "Expected digest:   " << std::get<2>(item) << std::endl
                << "Calculated digest: " << md_sha224.toHexString() << std::endl;
      if (std::get<2>(item) != md_sha224.toHexString())
      {
        std::cout << "ERROR: Message digest is not as expected!" << std::endl;
        return 1;
      }
    } //if short/long check
  } //for
  std::cout << "Passed test!" << std::endl;
  return 0;
}
