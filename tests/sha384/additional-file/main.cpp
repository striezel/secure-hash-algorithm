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

#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>
#include "../../../libthoro/filesystem/DirectoryFunctions.hpp"
#include "../../../libthoro/filesystem/FileFunctions.hpp"
#include "../../../libthoro/hash/sha384/sha384.hpp"
#include "../../../libthoro/hash/sha384/FileSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf>.
*/

const std::vector<std::tuple<std::size_t, char, std::string> > testData =
{
    // #1
    std::tuple<std::size_t, char, std::string>(0, '\0',
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
    // #2
    std::tuple<std::size_t, char, std::string>(111, '\0',
        "435770712c611be7293a66dd0dc8d1450dc7ff7337bfe115bf058ef2eb9bed09cee85c26963a5bcc0905dc2df7cc6a76"),
    // #3
    std::tuple<std::size_t, char, std::string>(112, '\0',
        "3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20"),
    // #4
    std::tuple<std::size_t, char, std::string>(113, '\0',
        "6be9af2cf3cd5dd12c8d9399ec2b34e66034fbd699d4e0221d39074172a380656089caafe8f39963f94cc7c0a07e3d21"),
    // #5
    std::tuple<std::size_t, char, std::string>(122, '\0',
        "12a72ae4972776b0db7d73d160a15ef0d19645ec96c7f816411ab780c794aa496a22909d941fe671ed3f3caee900bdd5"),
    // #6
    std::tuple<std::size_t, char, std::string>(1000, '\0',
        "aae017d4ae5b6346dd60a19d52130fb55194b6327dd40b89c11efc8222292de81e1a23c9b59f9f58b7f6ad463fa108ca"),
    // #7
    std::tuple<std::size_t, char, std::string>(1000, 0x41, /* A */
        "7df01148677b7f18617eee3a23104f0eed6bb8c90a6046f715c9445ff43c30d69e9e7082de39c3452fd1d3afd9ba0689"),
    // #8
    std::tuple<std::size_t, char, std::string>(1005, 0x55 /* U */,
        "1bb8e256da4a0d1e87453528254f223b4cb7e49c4420dbfa766bba4adba44eeca392ff6a9f565bc347158cc970ce44ec"),
    // #9
    std::tuple<std::size_t, char, std::string>(1000000, '\0',
        "8a1979f9049b3fff15ea3a43a4cf84c634fd14acad1c333fecb72c588b68868b66a994386dc0cd1687b9ee2e34983b81"),
    // #10
    std::tuple<std::size_t, char, std::string>(536870912, 0x5a, /* Z */
        "18aded227cc6b562cc7fb259e8f404549e52914531aa1c5d85167897c779cc4b25d0425fd1590e40bd763ec3f4311c1a"),
    // #11
    std::tuple<std::size_t, char, std::string>(1090519040, '\0',
        "83ab05ca483abe3faa597ad524d31291ae827c5be2b3efcb6391bfed31ccd937b6135e0378c6c7f598857a7c516f207a"),
    // #12
    std::tuple<std::size_t, char, std::string>(1610612798, 0x42, /* B */
        "cf852304f8d80209351b37ce69ca7dcf34972b4edb7817028ec55ab67ad3bc96eecb8241734258a85d2afce65d4571e2")
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

  //create temp file for tests
  std::string fileName = "";
  if (!libthoro::filesystem::File::createTemp(fileName))
  {
    std::cout << "Error: Could not create temporary file!"   << std::endl;
    return 1;
  }

  bool failed = false;
  for (auto && item : testData)
  {
    if (hashLongFiles || (std::get<0>(item)<= cShortMaximum))
    {
      //generate file from data
      std::ofstream stream;
      stream.open(fileName, std::ios_base::trunc | std::ios_base::binary | std::ios_base::out);
      if (!stream.good() || !stream.is_open())
      {
        std::cout << "Error: could not create/open temporary file!" << std::endl;
        return 1;
      }
      std::size_t i = 0;
      for (i=0; i<std::get<0>(item); ++i)
      {
        stream.put(std::get<1>(item));
      } //for
      if (!stream.good())
      {
        std::cout << "Error: Could not write data to temporary file!" << std::endl;
        stream.close();
        libthoro::filesystem::File::remove(fileName);
        return 1;
      }
      stream.close();

      //compute hash
      const SHA384::MessageDigest md_sha384 = SHA384::computeFromFile(fileName);
      std::cout << "Message: "<< std::get<0>(item) << " bytes of " << static_cast<unsigned int>(std::get<1>(item)) << std::endl
                << "Expected digest:   " << std::get<2>(item) << std::endl
                << "Calculated digest: " << md_sha384.toHexString() << std::endl;
      if (std::get<2>(item) != md_sha384.toHexString())
      {
        std::cout << "ERROR: Message digest is not as expected!" << std::endl;
        failed = true;
        /* libthoro::filesystem::File::remove(fileName);
        return 1; */
      }
    } //if short/long check
  } //for
  libthoro::filesystem::File::remove(fileName);
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
