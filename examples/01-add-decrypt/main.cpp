#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
//
#include <fmt/format.h>
//
#include <lyrahgames/log/log.hpp>
#include <lyrahgames/options/options.hpp>
//
#include <lyrahgames/cipher/cipher.hpp>

using namespace std;
using namespace fmt;
using namespace lyrahgames;

using options::attachment;
using options::flag;
using options::option_list;
option_list<flag<"help", "Print help message.", 'h'>,
            flag<"quiet", "Disable printing of info.", 'q'>,
            attachment<"input", "Provide file for decryption.", 'i'> >
    my_options{};

void print_help() {
  for_each(my_options, [](auto& x) {
    print("  {:<20}{:<40}\n", x.help(), x.description());
  });
}

int main(int argc, char* argv[]) {
  log::log log{};
  parse({argc, argv}, my_options);

  if (value<"help">(my_options)) {
    print_help();
    return 0;
  }

  if (value<"quiet">(my_options)) log.quiet = true;

  if (value<"input">(my_options) == "") {
    log.error("No file for decryption given.");
    return -1;
  }

  // Open given file.
  fstream file{value<"input">(my_options), ios::in};
  if (!file) {
    log.error(format("Failed to open '{}'.", value<"input">(my_options)));
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
