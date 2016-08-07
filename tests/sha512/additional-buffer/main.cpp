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
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include "../../../libthoro/hash/sha512/sha512.hpp"
#include "../../../libthoro/hash/sha512/BufferSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf>.
*/

const std::vector<std::tuple<std::size_t, char, std::string> > testData =
{
    // #1
    std::tuple<std::size_t, char, std::string>(0, '\0',
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    // #2
    std::tuple<std::size_t, char, std::string>(111, '\0',
        "77ddd3a542e530fd047b8977c657ba6ce72f1492e360b2b2212cd264e75ec03882e4ff0525517ab4207d14c70c2259ba88d4d335ee0e7e20543d22102ab1788c"),
    // #3
    std::tuple<std::size_t, char, std::string>(112, '\0',
        "2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952"),
    // #4
    std::tuple<std::size_t, char, std::string>(113, '\0',
        "0e67910bcf0f9ccde5464c63b9c850a12a759227d16b040d98986d54253f9f34322318e56b8feb86c5fb2270ed87f31252f7f68493ee759743909bd75e4bb544"),
    // #5
    std::tuple<std::size_t, char, std::string>(122, '\0',
        "4f3f095d015be4a7a7cc0b8c04da4aa09e74351e3a97651f744c23716ebd9b3e822e5077a01baa5cc0ed45b9249e88ab343d4333539df21ed229da6f4a514e0f"),
    // #6
    std::tuple<std::size_t, char, std::string>(1000, '\0',
        "ca3dff61bb23477aa6087b27508264a6f9126ee3a004f53cb8db942ed345f2f2d229b4b59c859220a1cf1913f34248e3803bab650e849a3d9a709edc09ae4a76"),
    // #7
    std::tuple<std::size_t, char, std::string>(1000, 0x41, /* A */
        "329c52ac62d1fe731151f2b895a00475445ef74f50b979c6f7bb7cae349328c1d4cb4f7261a0ab43f936a24b000651d4a824fcdd577f211aef8f806b16afe8af"),
    // #8
    std::tuple<std::size_t, char, std::string>(1005, 0x55 /* U */,
        "59f5e54fe299c6a8764c6b199e44924a37f59e2b56c3ebad939b7289210dc8e4c21b9720165b0f4d4374c90f1bf4fb4a5ace17a1161798015052893a48c3d161"),
    // #9
    std::tuple<std::size_t, char, std::string>(1000000, '\0',
        "ce044bc9fd43269d5bbc946cbebc3bb711341115cc4abdf2edbc3ff2c57ad4b15deb699bda257fea5aef9c6e55fcf4cf9dc25a8c3ce25f2efe90908379bff7ed"),
    // #10
    std::tuple<std::size_t, char, std::string>(536870912, 0x5a, /* Z */
        "da172279f3ebbda95f6b6e1e5f0ebec682c25d3d93561a1624c2fa9009d64c7e9923f3b46bcaf11d39a531f43297992ba4155c7e827bd0f1e194ae7ed6de4cac"),
    // #11
    std::tuple<std::size_t, char, std::string>(1090519040, '\0',
        "14b1be901cb43549b4d831e61e5f9df1c791c85b50e85f9d6bc64135804ad43ce8402750edbe4e5c0fc170b99cf78b9f4ecb9c7e02a157911d1bd1832d76784f"),
    // #12
    std::tuple<std::size_t, char, std::string>(1610612798, 0x42, /* B */
        "fd05e13eb771f05190bd97d62647157ea8f1f6949a52bb6daaedbad5f578ec59b1b8d6c4a7ecb2feca6892b4dc138771670a0f3bd577eea326aed40ab7dd58b1")
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
      //first parameter: allow long files
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
  uint8_t * buffer = NULL;

  bool failed = false;
  for (auto && item : testData)
  {
    if (hashLongData || (std::get<0>(item)<= cShortMaximum))
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
      // ---- copy data into buffer
      memset(buffer, std::get<1>(item), std::get<0>(item));

      //compute hash
      const SHA512::MessageDigest md_sha512 = SHA512::computeFromBuffer(buffer, std::get<0>(item)*8);
      std::cout << "Message: "<< std::get<0>(item) << " bytes of " << static_cast<unsigned int>(std::get<1>(item)) << std::endl
                << "Expected digest:   " << std::get<2>(item) << std::endl
                << "Calculated digest: " << md_sha512.toHexString() << std::endl;
      if (std::get<2>(item) != md_sha512.toHexString())
      {
        std::cout << "ERROR: Message digest is not as expected!" << std::endl;
        failed = true;
        /* delete[] buffer;
        buffer = nullptr;
        return 1; */
      }
      delete[] buffer;
      buffer = nullptr;
    } //if short/long check
  } //for
  if (!failed)
  {
    std::cout << "Passed test!" << std::endl;
    return 0;
  } //if
  else
  {
    std::cout << "ERROR: At least one test failed!" << std::endl;
    return 1;
  } //else
}
