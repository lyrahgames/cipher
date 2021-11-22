#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
//
#include <fmt/format.h>
//
#include <lyrahgames/log/log.hpp>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace fmt;
using namespace lyrahgames;

int main(int argc, char* argv[]) {
  log::log log{};
  log.quiet = true;

  if (argc != 2) {
    log.error("No file for decryption given.");
    return -1;
  }

  // Open given file.
  fstream file{argv[1], ios::in};
  if (!file) {
    log.error(format("Failed to open '{}'.", argv[1]));
    return -1;
  }

  // Determine size of file.
  file.seekg(0, ios::end);
  const auto len = file.tellg();
  file.seekg(0, ios::beg);

  // Read content of file into string.
  string content;
  content.resize(len);
  file.read(&content[0], len);

  //
  using block = cipher::ascii_block;
  using cipher = cipher::add<block>;
  cipher::key key{};

  log.info("Doing cryptanalysis for given file by counting frequencies.");
  key = cipher::frequency_analysis(' ', content);
  log.info(format("Estimated Key = '{}' ({}) ({:#x})", char(key.data), key.data,
                  key.data));
  log.info("Decrypt the given file with the estimated key.");
  cipher::decrypt(key, content);

  cout << content << endl;
}
