#include <bitset>
#include <filesystem>
#include <fstream>
#include <functional>
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

namespace args {

using czstring = const char*;

bool help_option = false;
bool version_option = false;
bool quiet_option = false;
bool encrypt_option = false;
bool decrypt_option = false;

czstring type_option = nullptr;
czstring key_option = nullptr;
czstring input_option = nullptr;
czstring output_option = nullptr;

inline void parse(int argc, czstring argv[]) {
  for (int i = 1; i < argc; ++i) {
    const auto str = string(argv[i]);

    if (str == "-h" || str == "--help") {
      help_option = true;
    }

    else if (str == "--version") {
      version_option = true;
    }

    else if (str == "-q" || str == "--quiet") {
      quiet_option = true;
    }

    else if (str == "-e" || str == "--encrypt") {
      encrypt_option = true;
    }

    else if (str == "-d" || str == "--decrypt") {
      decrypt_option = true;
    }

    else if (str == "-t" || str == "--type") {
      if (i + 1 >= argc) {
        log::error(format("No value given for '{}'", str));
        exit(-1);
      }
      ++i;
      type_option = argv[i];
    }

    else if (str == "-k" || str == "--key") {
      if (i + 1 >= argc) {
        log::error(format("No value given for '{}'", str));
        exit(-1);
      }
      ++i;
      key_option = argv[i];
    }

    else if (str == "-i" || str == "--input") {
      if (i + 1 >= argc) {
        log::error(format("No value given for '{}'", str));
        exit(-1);
      }
      ++i;
      input_option = argv[i];
    }

    else if (str == "-o" || str == "--output") {
      if (i + 1 >= argc) {
        log::error(format("No value given for '{}'", str));
        exit(-1);
      }
      ++i;
      output_option = argv[i];
    }

    else {
      log::error(format("Unknown option '{}'", str));
      exit(-1);
    }
  }
}

inline void print_help() {
  print(emphasis::bold, "SYNOPSIS\n\n");
  print("  {} [-h | --help]\n", "cipher");
  print("  {} --version\n", "cipher");
  print("  {} [options]\n", "cipher");
  print("\n");

  print(emphasis::bold, "DESCRIPTION\n\n");
  print(
      "  lyrahgames-cipher command line tool\n"
      "  to test en- and decryption algorithms.\n\n");

  print(emphasis::bold, "OPTIONS\n\n");
  print("  -h, --help        Display this message.\n");
  print("      --version     Print program version.\n");
  print("  -q, --quiet       Disable log output on console.\n");
  print("  -e, --encrypt     Set mode of operation to encryption.\n");
  print("  -d, --decrypt     Set mode of operation to decryption.\n");
  print("  -t, --type TYPE   Set cipher algorithm to TYPE in {}.\n",
        "{add | mul}");
  print("  -k, --key KEY     Provide the key for the cipher algorithm.\n");
  print(
      "  -i, --input FILE  Set input source for data to be en- or "
      "decrypted.\n");
  print(
      "  -o, --output FILE Set output file for processed data to be stored "
      "in.\n");
  print("\n");
}

}  // namespace args

int main(int argc, const char* argv[]) {
  args::parse(argc, argv);

  if (argc == 1 || args::help_option) {
    args::print_help();
    return 0;
  }

  if (args::version_option) {
    print("cipher (lyrahgames-cipher) version 0.1.0\n");
    return 0;
  }

  if (args::encrypt_option && args::decrypt_option) {
    log::error("Cannot encrypt and decrypt at the same time.");
    return -1;
  }

  if (args::quiet_option) log::quiet = true;

  if (args::encrypt_option) log::info("Mode of operation set to encryption.");

  if (args::decrypt_option) log::info("Mode of operation set to decryption.");

  if (args::type_option) {
    log::info(format("Cipher algorithm is {}.", args::type_option));
  }

  if (args::input_option) {
    log::info(format("Input file is '{}'.", args::input_option));
  } else {
    log::error("No input file given.");
  }

  if (args::output_option) {
    log::info(format("Output file is '{}'.", args::output_option));
  } else {
    log::error("No output file given.");
  }

  // // Read text from file and store it in string.
  // fstream file{argv[1], ios::in};
  // if (!file) {
  //   log::error(format("Failed to open file '{}'.", argv[1]));
  //   return -1;
  // }
  // log::info(format("Reading text from file '{}'.", argv[1]));
  // file.seekg(0, ios::end);
  // auto l = file.tellg();
  // file.seekg(0, ios::beg);
  // string text;
  // text.resize(l);
  // file.read(&text[0], l);

  // using block = cipher::ascii_block;
  // using cipher = cipher::add<block>;

  // log::info("Doing cryptanalysis for given file by counting frequencies.");

  // // Assume the most frequent character is the space sign.
  // const auto key = cipher::frequency_analysis(' ', text);

  // log::info(format("Estimated Key = '{}' ({}) ({:#x})", char(key.data),
  //                  key.data, key.data));

  // log::info("Decrypt the given file with the estimated key.");
  // cipher::decrypt(key, text);

  // print("{}\n", text);
}
