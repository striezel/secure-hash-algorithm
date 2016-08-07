/*
 -------------------------------------------------------------------------------
    This file is part of the SHA-256 hash calculator.
    Copyright (C) 2012, 2015, 2016  Dirk Stolle

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
 -------------------------------------------------------------------------------
*/

#include <iostream>
#include <set>
#include <string>
#include "../libstriezel/filesystem/file.hpp"
#include "../libstriezel/hash/sha512/sha512.hpp"
#include "../libstriezel/hash/sha512/FileSource.hpp"
#include "../libstriezel/hash/sha512/FileSourceUtility.hpp"
#include "../libstriezel/hash/sha384/sha384.hpp"
#include "../libstriezel/hash/sha384/FileSource.hpp"
#include "../libstriezel/hash/sha384/FileSourceUtility.hpp"
#include "../libstriezel/hash/sha256/sha256.hpp"
#include "../libstriezel/hash/sha256/FileSource.hpp"
#include "../libstriezel/hash/sha256/FileSourceUtility.hpp"
#include "../libstriezel/hash/sha224/sha224.hpp"
#include "../libstriezel/hash/sha224/FileSource.hpp"
#include "../libstriezel/hash/sha224/FileSourceUtility.hpp"
#include "../libstriezel/hash/sha1/sha1.hpp"
#include "../libstriezel/hash/sha1/FileSource.hpp"
#include "../libstriezel/hash/sha1/FileSourceUtility.hpp"

//return codes
const int rcInvalidParameter = 1;

void showGPLNotice()
{
  std::cout << "SHA-256 file hash calculator\n"
            << "  Copyright (C) 2012, 2015  Dirk Stolle\n"
            << "\n"
            << "  This program is free software: you can redistribute it and/or\n"
            << "  modify it under the terms of the GNU General Public License as published\n"
            << "  by the Free Software Foundation, either version 3 of the License, or\n"
            << "  (at your option) any later version.\n"
            << "\n"
            << "  This program is distributed in the hope that they will be useful,\n"
            << "  but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            << "  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
            << "  GNU General Public License for more details.\n"
            << "\n"
            << "  You should have received a copy of the GNU General Public License\n"
            << "  along with this program.  If not, see <http://www.gnu.org/licenses/>.\n"
            << "\n";
}

void showVersion()
{
  showGPLNotice();
  std::cout << "SHA-256 file hash calculator, version 1.4, 2015-08-06\n";
}

void showHelp()
{
  std::cout << "\nsha256 [--sha1 | --sha224 | --sha256 | --sha384 | --sha512] FILENAME\n"
            << "\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version        - displays the version of the program and quits\n"
            << "  -v               - same as --version\n"
            << "  FILENAME         - set path to file that should be hashed. Can be repeated\n"
            << "                     multiple times. Has to appear at least once.\n"
            << "  --sha1           - use SHA-1 instead of SHA-256 to hash files.\n"
            << "  --sha224         - use SHA-224 instead of SHA-256 to hash files.\n"
            << "  --sha256         - use SHA-256 to hash files. This option is active by\n"
            << "                     default.\n"
            << "  --sha384         - use SHA-384 instead of SHA-384 to hash files.\n"
            << "  --sha512         - use SHA-512 instead of SHA-256 to hash files.\n";
}

int main(int argc, char **argv)
{
  std::set<std::string> files;

  enum SHAHashType { htUnspecified, htSHA1, htSHA224, htSHA256, htSHA384, htSHA512 };

  SHAHashType hashType = htUnspecified;

  if ((argc>1) and (argv!=NULL))
  {
    int i=1;
    while (i<argc)
    {
      if (argv[i]!=NULL)
      {
        const std::string param = std::string(argv[i]);
        //help parameter
        if ((param=="--help") or (param=="-?") or (param=="/?"))
        {
          showHelp();
          return 0;
        }//if help wanted
        //version information requested?
        else if ((param=="--version") or (param=="-v"))
        {
          showVersion();
          return 0;
        }//version
        else if ((param=="--sha1") or (param=="--sha-1") or (param=="--sha160")
              or (param=="--sha-160"))
        {
          if (hashType==htSHA1)
          {
            std::cout << "Error: parameter "<<param<<" must not occur more than once!\n";
            return rcInvalidParameter;
          }
          if (hashType!=htUnspecified)
          {
            std::cout << "Error: parameter "<<param<<" must not occur after "
                      << "hash type has already been set!\n";
            return rcInvalidParameter;
          }
          hashType = htSHA1;
        }//sha-1
        else if ((param=="--sha224") or (param=="--sha-224"))
        {
          if (hashType==htSHA224)
          {
            std::cout << "Error: parameter " << param << " must not occur more than once!\n";
            return rcInvalidParameter;
          }
          if (hashType!=htUnspecified)
          {
            std::cout << "Error: parameter " << param << " must not occur "
                      << "after hash type has already been set!\n";
            return rcInvalidParameter;
          }
          hashType = htSHA224;
        }//sha-224
        else if ((param=="--sha256") or (param=="--sha-256"))
        {
          if (hashType==htSHA256)
          {
            std::cout << "Error: parameter "<<param<<" must not occur more than once!\n";
            return rcInvalidParameter;
          }
          if (hashType!=htUnspecified)
          {
            std::cout << "Error: parameter "<<param<<" must not occur after "
                      << "hash type has already been set!\n";
            return rcInvalidParameter;
          }
          hashType = htSHA256;
        }//sha-256
        else if ((param=="--sha384") or (param=="--sha-384"))
        {
          if (hashType==htSHA384)
          {
            std::cout << "Error: parameter " << param << " must not occur more than once!\n";
            return rcInvalidParameter;
          }
          if (hashType!=htUnspecified)
          {
            std::cout << "Error: parameter " << param << " must not occur "
                      << "after hash type has already been set!\n";
            return rcInvalidParameter;
          }
          hashType = htSHA384;
        }//sha-384
        else if ((param=="--sha512") or (param=="--sha-512"))
        {
          if (hashType==htSHA512)
          {
            std::cout << "Error: parameter " << param << " must not occur more than once!\n";
            return rcInvalidParameter;
          }
          if (hashType!=htUnspecified)
          {
            std::cout << "Error: parameter " << param << " must not occur "
                      << "after hash type has already been set!\n";
            return rcInvalidParameter;
          }
          hashType = htSHA512;
        }//sha-512
        else
        {
          //should be filename
          if (libstriezel::filesystem::file::exists(param))
          {
            //add file to list
            files.insert(param);
          }
          else
          {
            std::cout << "Invalid parameter/filename given: \""<<param
                      << "\" does not name an existing file!\n"
                      << "Use --help to get a list of valid parameters.\n";
            return rcInvalidParameter;
          }
        }
      }//parameter exists
      else
      {
        std::cout << "Parameter at index "<<i<<" is NULL.\n";
        return rcInvalidParameter;
      }
      ++i;//on to next parameter
    }//while
  }//if arguments present
  else
  {
    std::cout << "You have to specify certain parameters for this program to run properly.\n"
              << "Use --help to get a list of valid parameters.\n";
    return rcInvalidParameter;
  }

  if (files.empty())
  {
    std::cout << "You have to specify certain parameters for this program to run properly.\n"
              << "Use --help to get a list of valid parameters.\n";
    return rcInvalidParameter;
  }

  // Set default hash algorithm, if no choice was made.
  if (hashType==htUnspecified)
    hashType = htSHA256;

  std::cout << "Hashing file(s), this may take a while..." << std::endl;

  std::set<std::string>::const_iterator iter = files.begin();
  SHA512::MessageDigest hash512;
  SHA384::MessageDigest hash384;
  SHA256::MessageDigest hash256;
  SHA224::MessageDigest hash224;
  SHA1::MessageDigest hash160;
  while (iter!=files.end())
  {
    switch (hashType)
    {
      case htSHA1:
           hash160 = SHA1::computeFromFile(*iter);
           std::cout << hash160.toHexString() << "  " << *iter << std::endl;
           break;
      case htSHA224:
           hash224 = SHA224::computeFromFile(*iter);
           std::cout << hash224.toHexString() << "  " << *iter << std::endl;
           break;
      case htSHA384:
           hash384 = SHA384::computeFromFile(*iter);
           std::cout << hash384.toHexString() << "  " << *iter << std::endl;
           break;
      case htSHA512:
           hash512 = SHA512::computeFromFile(*iter);
           std::cout << hash512.toHexString() << "  " << *iter << std::endl;
           break;
      default:
           hash256 = SHA256::computeFromFile(*iter);
           std::cout << hash256.toHexString() << "  " << *iter << std::endl;
           break;
    }//swi
    ++iter;
  }//while

  return 0;
}
