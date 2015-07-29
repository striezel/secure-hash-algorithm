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
#include <tuple>
#include <vector>
#include "../../../libthoro/filesystem/DirectoryFunctions.hpp"
#include "../../../libthoro/filesystem/FileFunctions.hpp"
#include "../../../libthoro/hash/sha-256.hpp"

/*
  The following example test messages and digests are take from
  <http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA2_Additional.pdf>.
*/

const std::vector<std::tuple<std::size_t, char, std::string> > testData =
{
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

  if (!libthoro::filesystem::Directory::exists(fileDir))
  {
    std::cout << "Error: Directory " << fileDir << " does not exist!"
              << std::endl;
    return 1;
  }
  //add trailing slash, if it is missing
  fileDir = libthoro::filesystem::slashify(fileDir);

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
  SHA256::MessageDigest md_sha256 = SHA256::computeFromFile(fileDir+"file_1_byte_0xbd.dat");
  std::cout << "File: file_1_byte_0xbd.dat" << std::endl
            << "Expected digest:   68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b" << std::endl
            << "Calculated digest: " << md_sha256.toHexString() << std::endl;
  if ("68325720aabd7c82f30f554b313d0570c95accbb7dc4b5aae11204c08ffe732b" != md_sha256.toHexString())
  {
    std::cout << "ERROR: Message digest is not as expected!" << std::endl;
    return 1;
  }
  //hash second file
  md_sha256 = SHA256::computeFromFile(fileDir+"file_4_bytes_0xc98c8e55.dat");
  std::cout << "File: file_4_bytes_0xc98c8e55.dat" << std::endl
            << "Expected digest:   7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504" << std::endl
            << "Calculated digest: " << md_sha256.toHexString() << std::endl;
  if ("7abc22c0ae5af26ce93dbb94433a0e0b2e119d014f8e7f65bd56c61ccccd9504" != md_sha256.toHexString())
  {
    std::cout << "ERROR: Message digest is not as expected!" << std::endl;
    return 1;
  }

  //create temp file for tests
  std::string fileName = "";
  if (!libthoro::filesystem::File::createTemp(fileName))
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
        libthoro::filesystem::File::remove(fileName);
        return 1;
      }
      stream.close();

      //reset hash
      md_sha256.setToNull();
      md_sha256 = SHA256::computeFromFile(fileName);
      std::cout << "Message: "<< std::get<0>(item) << " bytes of " << static_cast<unsigned int>(std::get<1>(item)) << std::endl
                << "Expected digest:   " << std::get<2>(item) << std::endl
                << "Calculated digest: " << md_sha256.toHexString() << std::endl;
      if (std::get<2>(item) != md_sha256.toHexString())
      {
        std::cout << "ERROR: Message digest is not as expected!" << std::endl;
        libthoro::filesystem::File::remove(fileName);
        return 1;
      }
    } //if short/long check
  } //for
  libthoro::filesystem::File::remove(fileName);
  std::cout << "Passed test!" << std::endl;
  return 0;
}
