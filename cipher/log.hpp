#pragma once
#include <fmt/color.h>
#include <fmt/format.h>
#include <fmt/ostream.h>
//
#ifdef __clang__
#include <experimental/source_location>
namespace application::log {
using source_location = std::experimental::source_location;
}
#else
#include <source_location>
namespace application::log {
using source_location = std::source_location;
}
#endif

namespace application::log {

using namespace std;
using namespace fmt;
using namespace fmt::literals;

static constexpr size_t indent = 10;

bool quiet = false;

inline auto to_string(source_location location) {
  return format(
      "{} {}:",
      format(emphasis::bold, "{}:{}:{}: ",  //
             location.file_name(), location.line(), location.column()),
      location.function_name());
}

inline auto prefix(auto&& style, auto&& str) {
  return format(forward<decltype(style)>(style), "{0:<{1}}",
                forward<decltype(str)>(str), indent);
}

inline auto indent_string() {
  return format("{0:<{1}}", "", indent);
}

inline auto log(auto& stream,
                auto&& pre,
                auto&& x,
                source_location location = source_location::current()) {
  print(stream, "{}{}\n{}{}\n\n", forward<decltype(pre)>(pre),
        to_string(location), indent_string(), forward<decltype(x)>(x));
}

inline void info(auto&& x,
                 source_location location = source_location::current()) {
  if (quiet) return;
  log(stdout, prefix(fg(color::green), "INFO:"), forward<decltype(x)>(x),
      location);
}

inline void warning(auto&& x,
                    source_location location = source_location::current()) {
  if (quiet) return;
  log(stderr, prefix(fg(color::orange), "WARNING:"), forward<decltype(x)>(x),
      location);
}

inline void error(auto&& x,
                  source_location location = source_location::current()) {
  log(stderr, prefix(fg(color::red), "ERROR:"), forward<decltype(x)>(x),
      location);
}

}  // namespace application::log
