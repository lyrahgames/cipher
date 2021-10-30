#include <bitset>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
//
#include <lyrahgames/cipher/cipher.hpp>
//
#include "log.hpp"

using namespace std;
using namespace fmt;
using namespace lyrahgames;
using namespace application;

inline auto string_from_file(const filesystem::path& path) -> string {
  fstream file{path, ios::in};
  file.seekg(0, ios::end);
  auto l = file.tellg();
  file.seekg(0, ios::beg);
  string text;
  text.resize(l);
  file.read(&text[0], l);
  return text;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    log::error("Command-line arguments are wrong.");
    return -1;
  }

  // Read text from file and store it in string.
  fstream file{argv[1], ios::in};
  if (!file) {
    log::error(format("Failed to open file '{}'.", argv[1]));
    return -1;
  }
  log::info(format("Reading text from file '{}'.", argv[1]));
  file.seekg(0, ios::end);
  auto l = file.tellg();
  file.seekg(0, ios::beg);
  string text;
  text.resize(l);
  file.read(&text[0], l);

  using block = cipher::ascii_block;
  using cipher = cipher::add<block>;

  log::info("Doing cryptanalysis for given file by counting frequencies.");

  // Assume the most frequent character is the space sign.
  const auto key = cipher::frequency_analysis(' ', text);

  log::info(format("Estimated Key = '{}' ({}) ({:#x})", char(key.data),
                   key.data, key.data));

  log::info("Decrypt the given file with the estimated key.");
  cipher::decrypt(key, text);

  print("{}\n", text);
}
