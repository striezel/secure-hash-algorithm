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
#include "../../../libstriezel/hash/sha256/sha256.hpp"
#include "../../../libstriezel/hash/sha256/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf>.
*/

const std::vector<std::tuple<std::size_t, char, std::string> > testData =
{
    // #1
    std::tuple<std::size_t, char, std::string>(1, 0xbd,
        "68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b"),
    // example #2 is listed below
    // #3
    std::tuple<std::size_t, char, std::string>(55, '\0',
        "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7"),
    // #4
    std::tuple<std::size_t, char, std::string>(56, '\0',
        "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"),
    // #5
    std::tuple<std::size_t, char, std::string>(57, '\0',
        "65a16cb7861335d5ace3c60718b5052e44660726da4cd13bb745381b235a1785"),
    // #6
    std::tuple<std::size_t, char, std::string>(64, '\0',
        "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    // #7
    std::tuple<std::size_t, char, std::string>(1000, '\0',
        "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53"),
    // #8
    std::tuple<std::size_t, char, std::string>(1000, 0x41 /* A */,
        "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4"),
    // #9
    std::tuple<std::size_t, char, std::string>(1005, 0x55 /* U */,
        "f4d62ddec0f3dd90ea1380fa16a5ff8dc4c54b21740650f24afc4120903552b0"),
    // #10
    std::tuple<std::size_t, char, std::string>(1000000, '\0',
        "d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025"),

    // #11
    std::tuple<std::size_t, char, std::string>(536870912, 0x5a /* 'Z' */,
        "15a1868c12cc53951e182344277447cd0979536badcc512ad24c67e9b2d4f3dd"),
    // #12
    std::tuple<std::size_t, char, std::string>(1090519040, '\0',
        "461c19a93bd4344f9215f5ec64357090342bc66b15a148317d276e31cbc20b53"),
    // #13
    std::tuple<std::size_t, char, std::string>(1610612798, 0x42 /* 'B' */,
        "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea")
};

// maximum file size for "short" file tests
const std::size_t cShortMaximum = 1024*1024;

int main(int argc, char** argv)
{
  //switch for hashing longer files (default: false)
  bool hashLongFiles = false;

  if (argc>1)
  {
    if (argv!=nullptr)
    {
      //first parameter: allow long files
      if (argv[1] != nullptr)
      {
        const std::string param(argv[1]);
        if (param=="--long" || param=="-l")
        {
          hashLongFiles = true;
        } //if
        else
        {
          std::cout << "Error: Invalid parameter " << param << "!" << std::endl;
          return 1;
        }
      } //if argv[1] exists
    } //if argv != null
  } //if args are present

  if (!hashLongFiles)
  {
    std::cout << "Info: Skipping test data with messages longer than "
              << cShortMaximum << " bytes." << std::endl;
  }
  else
  {
    std::cout << "Info: Processing test data with messages longer than "
              << cShortMaximum << " bytes, too." << std::endl;
  }

  uint8_t * buffer = nullptr;

  //fill second example directly into buffer
  buffer = new uint8_t[4];
  #if BYTE_ORDER == LITTLE_ENDIAN
  const uint32_t cSource4Bytes = 0x558e8cc9;
  #else
  const uint32_t cSource4Bytes = 0xc98c8e55;
  #endif
  memcpy(buffer, &cSource4Bytes, 4);

  //hash second buffer
  SHA256::MessageDigest md_sha256 = SHA256::computeFromBuffer(buffer, 32);
  delete[] buffer;
  buffer = nullptr;
  std::cout << "Buffer: 4 bytes: 0xc98c8e55" << std::endl
            << "Expected digest:   7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504" << std::endl
            << "Calculated digest: " << md_sha256.toHexString() << std::endl;
  if ("7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504" != md_sha256.toHexString())
  {
    std::cout << "ERROR: Message digest is not as expected!" << std::endl;
    return 1;
  }

  for (auto && item : testData)
  {
    if (hashLongFiles || (std::get<0>(item)<= cShortMaximum))
    {
      //generate buffer from data
      try
      {
        buffer = new uint8_t[std::get<0>(item)];
      }
      catch(...)
      {
        std::cout << "Error: Could not create buffer of " << std::get<0>(item)
                  << " bytes. Aborting test." << std::endl;
        return 1;
      } //try-catch
      memset(buffer, std::get<1>(item), std::get<0>(item));

      //reset hash
      md_sha256.setToNull();
      md_sha256 = SHA256::computeFromBuffer(buffer, std::get<0>(item)*8);
      delete[] buffer;
      buffer = nullptr;
      std::cout << "Message: "<< std::get<0>(item) << " bytes of " << static_cast<unsigned int>(std::get<1>(item)) << std::endl
                << "Expected digest:   " << std::get<2>(item) << std::endl
                << "Calculated digest: " << md_sha256.toHexString() << std::endl;
      if (std::get<2>(item) != md_sha256.toHexString())
      {
        std::cout << "ERROR: Message digest is not as expected!" << std::endl;
        return 1;
      }
    } //if short/long check
  } //for
  std::cout << "Passed test!" << std::endl;
  return 0;
}
