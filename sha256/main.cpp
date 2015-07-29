/*
 -------------------------------------------------------------------------------
    This file is part of the SHA-256 hash calculator.
    Copyright (C) 2012 Thoronador

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
#include "../libthoro/filesystem/FileFunctions.hpp"
#include "../libthoro/hash/sha-256.hpp"
#include "../libthoro/hash/sha-1.hpp"

//return codes
const int rcInvalidParameter = 1;

void showGPLNotice()
{
  std::cout << "SHA-256 file hash calculator\n"
            << "  Copyright (C) 2012 Thoronador\n"
            << "\n"
            << "  This programme is free software: you can redistribute it and/or\n"
            << "  modify it under the terms of the GNU General Public License as published\n"
            << "  by the Free Software Foundation, either version 3 of the License, or\n"
            << "  (at your option) any later version.\n"
            << "\n"
            << "  This programme is distributed in the hope that they will be useful,\n"
            << "  but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
            << "  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
            << "  GNU General Public License for more details.\n"
            << "\n"
            << "  You should have received a copy of the GNU General Public License\n"
            << "  along with this programme.  If not, see <http://www.gnu.org/licenses/>.\n"
            << "\n";
}

void showVersion()
{
  showGPLNotice();
  std::cout << "SHA-256 file hash calculator, version 1.1, 2012-09-18\n";
}

void showHelp()
{
  std::cout << "\nsha256 [--sha1 | --sha256] FILENAME\n"
            << "\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version        - displays the version of the programme and quits\n"
            << "  -v               - same as --version\n"
            << "  FILENAME         - set path to file that should be hashed. Can be repeated\n"
            << "                     multiple times.\n"
            << "  --sha1           - use SHA-1 instead of SHA-256 to hash files.\n"
            << "  --sha256         - use SHA-256 to hash files. This option is active by\n"
            << "                     default.\n";
}

int main(int argc, char **argv)
{
  std::set<std::string> files;

  enum SHAHashType {htUnspecified, htSHA1, htSHA256 };

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
        else
        {
          //should be filename
          if (libthoro::filesystem::File::exists(param))
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
    std::cout << "You have to specify certain parameters for this programme to run properly.\n"
              << "Use --help to get a list of valid parameters.\n";
    return rcInvalidParameter;
  }

  if (hashType==htUnspecified) hashType = htSHA256;

  std::cout << std::endl << "Hashing file(s), this may take a while..." << std::endl;

  std::set<std::string>::const_iterator iter = files.begin();
  SHA256::MessageDigest hash256;
  SHA1::MessageDigest hash160;
  while (iter!=files.end())
  {
    switch (hashType)
    {
      case htSHA1:
           hash160 = SHA1::computeFromFile(*iter);
           std::cout << hash160.toHexString() << "  " << *iter << std::endl;
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
