/*
 -----------------------------------------------------------------------------
    This file is part of a test suite for a secure hashing algorithm program.
    Copyright (C) 2015, 2016  Dirk Stolle

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
#include "../../../libstriezel/filesystem/directory.hpp"
#include "../../../libstriezel/filesystem/file.hpp"
#include "../../../libstriezel/hash/sha224/sha224.hpp"
#include "../../../libstriezel/hash/sha224/FileSourceUtility.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf>.
*/

const std::vector<std::tuple<std::size_t, char, std::string> > testData =
{
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
  if (argc<2)
  {
    std::cout << "Not enough command line arguments!" << std::endl;
    return 1;
  }

  //directory for sample files
  std::string fileDir = "";
  //switch for hashing longer files (default: false)
  bool hashLongFiles = false;

  if (argc>1)
  {
    if (argv!=nullptr)
    {
      //first parameter: directory with first test files
      if (argv[1] != nullptr)
      {
        fileDir = std::string(argv[1]);
      } //if argv[1] is set
      //second parameter: allow long files
      if (argv[2] != nullptr)
      {
        const std::string param(argv[2]);
        if (param=="--long" || param=="-l")
        {
          hashLongFiles = true;
        } //if
        else
        {
          std::cout << "Error: Invalid parameter " << param << "!" << std::endl;
          return 1;
        }
      } //if argv[2] exists

    } //if argv != null
  } //if args are present

  if (!libstriezel::filesystem::directory::exists(fileDir))
  {
    std::cout << "Error: Directory " << fileDir << " does not exist!"
              << std::endl;
    return 1;
  }
  //add trailing slash, if it is missing
  fileDir = libstriezel::filesystem::slashify(fileDir);

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

  //hash first file
  SHA224::MessageDigest md_sha224 = SHA224::computeFromFile(fileDir+"file_1_byte_0xff.dat");
  std::cout << "File: file_1_byte_0xff.dat" << std::endl
            << "Expected digest:   e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5" << std::endl
            << "Calculated digest: " << md_sha224.toHexString() << std::endl;
  if ("e33f9d75e6ae1369dbabf81b96b4591ae46bba30b591a6b6c62542b5" != md_sha224.toHexString())
  {
    std::cout << "ERROR: Message digest is not as expected!" << std::endl;
    return 1;
  }
  //hash second file
  md_sha224 = SHA224::computeFromFile(fileDir+"file_4_bytes_0xe5e09924.dat");
  std::cout << "File: file_4_bytes_0xe5e09924.dat" << std::endl
            << "Expected digest:   fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d" << std::endl
            << "Calculated digest: " << md_sha224.toHexString() << std::endl;
  if ("fd19e74690d291467ce59f077df311638f1c3a46e510d0e49a67062d" != md_sha224.toHexString())
  {
    std::cout << "ERROR: Message digest is not as expected!" << std::endl;
    return 1;
  }

  //create temp file for tests
  std::string fileName = "";
  if (!libstriezel::filesystem::file::createTemp(fileName))
  {
    std::cout << "Error: Could not create temporary file!"   << std::endl;
    return 1;
  }

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
        libstriezel::filesystem::file::remove(fileName);
        return 1;
      }
      stream.close();

      //reset hash
      md_sha224.setToNull();
      md_sha224 = SHA224::computeFromFile(fileName);
      std::cout << "Message: "<< std::get<0>(item) << " bytes of " << static_cast<unsigned int>(std::get<1>(item)) << std::endl
                << "Expected digest:   " << std::get<2>(item) << std::endl
                << "Calculated digest: " << md_sha224.toHexString() << std::endl;
      if (std::get<2>(item) != md_sha224.toHexString())
      {
        std::cout << "ERROR: Message digest is not as expected!" << std::endl;
        libstriezel::filesystem::file::remove(fileName);
        return 1;
      }
    } //if short/long check
  } //for
  libstriezel::filesystem::file::remove(fileName);
  std::cout << "Passed test!" << std::endl;
  return 0;
}
