/// @file 7b.hpp
/// @brief A single-header C++ build system.
/// @author starssxhfdmh
/// @copyright Copyright (c) 2026 starssxhfdmh. MIT License.
/// @version 1.1.1
///
/// @details
/// 7b is a lightweight, header-only build system written in C++17.
/// It allows you to write your build logic in pure C++, freeing you
/// from the complexities of CMake and other build systems.
///
/// @par Features
/// - Header-only: Just include and use
/// - Self-rebuilding: Automatically recompiles when build script changes
/// - Parallel compilation: Utilizes multiple CPU cores
/// - Incremental builds: Only recompiles changed files
/// - pkg-config integration: Easy dependency management
/// - Cross-platform: Works on Linux and Windows
///
/// @par Quick Start
/// 1. Create build.cpp:
/// @code{.cpp}
/// #include "7b.hpp"
///
/// int main(int argc, char** argv) {
///     SB_INIT(argc, argv);
///     sb::Project("myapp")
///         .Sources({"src/main.cpp"})
///         .Build();
///     return 0;
/// }
/// @endcode
///
/// 2. Compile: `g++ -std=c++17 build.cpp -o build`
/// 3. Run: `./build`
///
/// @par Configuration Macros
/// Define these before including 7b.hpp:
/// | Macro | Description |
/// |-------|-------------|
/// | @c SB_QUIET | Minimal output (errors only) |
/// | @c SB_VERBOSE | Extra detailed output |
/// | @c SB_NO_COLORS | Disable colored output |
/// | @c SB_CXX | Override compiler (default: g++) |
/// | @c SB_CACHE_DIR | Override cache directory (default: .7b) |
/// | @c SB_DEBUG_FLAGS | Override default debug flags |
/// | @c SB_RELEASE_FLAGS | Override default release flags |
///
/// @par License
/// MIT License. See the license text at the top of this file.

#ifndef SEVENB_HPP_
#define SEVENB_HPP_

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
/// @brief Windows compatibility typedef for process ID.
typedef HANDLE pid_t;
#define SB_INVALID_PID INVALID_HANDLE_VALUE
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/wait.h>
#include <unistd.h>
#define SB_INVALID_PID (-1)
#else
#include <sys/wait.h>
#include <unistd.h>
#define SB_INVALID_PID (-1)
#endif

/// @def SB_CXX
/// @brief Default C++ compiler to use.
/// @details Override by defining before including 7b.hpp.
#ifndef SB_CXX
#define SB_CXX "g++"
#endif

/// @def SB_CACHE_DIR
/// @brief Directory for storing build cache and object files.
/// @details Override by defining before including 7b.hpp.
#ifndef SB_CACHE_DIR
#define SB_CACHE_DIR ".7b"
#endif

/// @def SB_DEBUG_FLAGS
/// @brief Default compiler flags for debug builds.
/// @details Override by defining before including 7b.hpp.
#ifndef SB_DEBUG_FLAGS
#define SB_DEBUG_FLAGS "-g", "-O0", "-Wall", "-Wextra"
#endif

/// @def SB_RELEASE_FLAGS
/// @brief Default compiler flags for release builds.
/// @details Override by defining before including 7b.hpp.
#ifndef SB_RELEASE_FLAGS
#define SB_RELEASE_FLAGS "-O2", "-DNDEBUG", "-Wall"
#endif

/// @namespace sb
/// @brief Main namespace for the 7b build system.
/// @details Contains all classes, functions, and utilities for building C++
/// projects.
namespace sb {

class Cmd;
class Project;

/// @enum OutputType
/// @brief Type of build output.
enum class OutputType {
  Executable, ///< Build an executable
  StaticLib,  ///< Build a static library (.a/.lib)
  SharedLib   ///< Build a shared library (.so/.dll/.dylib)
};

/// @namespace sb::detail
/// @brief Internal implementation details.
/// @warning Users should not rely on anything in this namespace.
namespace detail {

#ifdef SB_NO_COLORS
/// @brief ANSI reset code (disabled).
inline constexpr const char *kColorReset = "";
/// @brief ANSI red color code (disabled).
inline constexpr const char *kColorRed = "";
/// @brief ANSI green color code (disabled).
inline constexpr const char *kColorGreen = "";
/// @brief ANSI yellow color code (disabled).
inline constexpr const char *kColorYellow = "";
/// @brief ANSI cyan color code (disabled).
inline constexpr const char *kColorCyan = "";
#else
/// @brief ANSI escape code to reset terminal color.
inline constexpr const char *kColorReset = "\033[0m";
/// @brief ANSI escape code for red text.
inline constexpr const char *kColorRed = "\033[31m";
/// @brief ANSI escape code for green text.
inline constexpr const char *kColorGreen = "\033[32m";
/// @brief ANSI escape code for yellow text.
inline constexpr const char *kColorYellow = "\033[33m";
/// @brief ANSI escape code for cyan text.
inline constexpr const char *kColorCyan = "\033[36m";
#endif

/// @brief Maximum file size for hashing (100MB).
inline constexpr size_t kMaxHashFileSize = 100 * 1024 * 1024;

/// @brief Windows executable extension length.
inline constexpr size_t kExeExtLen = 4;

/// @brief Library prefix length on Unix.
inline constexpr size_t kLibPrefixLen = 3;

} // namespace detail

/// @brief Logs an error message to stderr.
/// @param msg The error message to display.
/// @note Error messages are always shown regardless of SB_QUIET setting.
inline void Error(std::string_view msg) {
  std::cerr << detail::kColorRed << "[7b] ERROR: " << detail::kColorReset << msg
            << "\n";
}

/// @brief Logs a warning message to stderr.
/// @param msg The warning message to display.
/// @note Hidden when SB_QUIET is defined.
inline void Warn([[maybe_unused]] std::string_view msg) {
#ifndef SB_QUIET
  std::cerr << detail::kColorYellow << "[7b] WARN: " << detail::kColorReset
            << msg << "\n";
#endif
}

/// @brief Logs an informational message to stdout.
/// @param msg The info message to display.
/// @note Hidden when SB_QUIET is defined.
inline void Log([[maybe_unused]] std::string_view msg) {
#ifndef SB_QUIET
  std::cout << detail::kColorGreen << "[7b] " << detail::kColorReset << msg
            << "\n";
#endif
}

/// @brief Logs a verbose debug message to stdout.
/// @param msg The verbose message to display.
/// @note Only shown when SB_VERBOSE is defined.
inline void Verbose([[maybe_unused]] std::string_view msg) {
#ifdef SB_VERBOSE
  std::cout << detail::kColorCyan << "[7b] " << detail::kColorReset << msg
            << "\n";
#endif
}

namespace detail {

/// @brief Computes FNV-1a 64-bit hash of data.
/// @param data Pointer to the data to hash.
/// @param len Length of the data in bytes.
/// @return The computed 64-bit hash value.
/// @details Uses the Fowler-Noll-Vo hash function variant 1a,
///          which provides good distribution for file content hashing.
inline uint64_t Fnv1aHash(const uint8_t *data, size_t len) {
  constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
  constexpr uint64_t kFnvPrime = 1099511628211ULL;

  uint64_t hash = kFnvOffsetBasis;
  for (size_t i = 0; i < len; ++i) {
    hash ^= static_cast<uint64_t>(data[i]);
    hash *= kFnvPrime;
  }
  return hash;
}

/// @brief Computes hash of a file's contents.
/// @param path Path to the file to hash.
/// @return The hash value, or std::nullopt if the file cannot be read
///         or exceeds the maximum file size limit.
/// @note Files larger than 100MB will return std::nullopt.
inline std::optional<uint64_t> HashFile(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    return std::nullopt;
  }

  auto size = file.tellg();
  if (size <= 0) {
    return Fnv1aHash(nullptr, 0);
  }

  // Prevent memory exhaustion from extremely large files
  if (static_cast<size_t>(size) > kMaxHashFileSize) {
    return std::nullopt;
  }

  file.seekg(0, std::ios::beg);
  std::vector<uint8_t> buffer(static_cast<size_t>(size));
  if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
    return std::nullopt;
  }

  return Fnv1aHash(buffer.data(), buffer.size());
}

/// @brief Converts a 64-bit hash to a hexadecimal string.
/// @param hash The hash value to convert.
/// @return A 16-character lowercase hexadecimal string.
inline std::string HashToHex(uint64_t hash) {
  char buf[17];
  std::snprintf(buf, sizeof(buf), "%016llx",
                static_cast<unsigned long long>(hash));
  return std::string(buf);
}

/// @brief Computes hash of a string.
/// @param str The string to hash.
/// @return The computed 64-bit hash value.
inline uint64_t HashString(const std::string &str) {
  return Fnv1aHash(reinterpret_cast<const uint8_t *>(str.data()), str.size());
}

/// @brief Encodes a string to hex for safe cache storage.
/// @param str The string to encode.
/// @return Hex-encoded string.
inline std::string EncodePathToHex(const std::string &str) {
  std::string result;
  result.reserve(str.size() * 2);
  for (unsigned char c : str) {
    char buf[3];
    std::snprintf(buf, sizeof(buf), "%02x", c);
    result += buf;
  }
  return result;
}

/// @brief Decodes a hex string back to original path.
/// @param hex The hex string to decode.
/// @return Decoded string, or empty on error.
inline std::string DecodeHexToPath(const std::string &hex) {
  if (hex.length() % 2 != 0) {
    return "";
  }

  std::string result;
  result.reserve(hex.length() / 2);

  for (size_t i = 0; i < hex.length(); i += 2) {
    unsigned int byte = 0;
    char h = hex[i];
    char l = hex[i + 1];

    if (h >= '0' && h <= '9')
      byte = static_cast<unsigned int>(h - '0') << 4;
    else if (h >= 'a' && h <= 'f')
      byte = static_cast<unsigned int>(h - 'a' + 10) << 4;
    else if (h >= 'A' && h <= 'F')
      byte = static_cast<unsigned int>(h - 'A' + 10) << 4;
    else
      return "";

    if (l >= '0' && l <= '9')
      byte |= static_cast<unsigned int>(l - '0');
    else if (l >= 'a' && l <= 'f')
      byte |= static_cast<unsigned int>(l - 'a' + 10);
    else if (l >= 'A' && l <= 'F')
      byte |= static_cast<unsigned int>(l - 'A' + 10);
    else
      return "";

    result += static_cast<char>(byte);
  }
  return result;
}

/// @brief Parses #include directives from a source file.
/// @param source Path to source file.
/// @param include_dirs List of include directories to search.
/// @return Set of resolved header file paths.
inline std::unordered_set<std::string>
ParseIncludes(const std::filesystem::path &source,
              const std::vector<std::string> &include_dirs) {
  std::unordered_set<std::string> headers;
  std::ifstream file(source);
  if (!file) {
    return headers;
  }

  // Static regex to avoid recompilation on every call (performance + ReDoS
  // mitigation)
  static const std::regex include_regex(
      R"(^\s*#\s*include\s*["<]([^">]+)[">])");
  std::string line;
  auto source_dir = source.parent_path();

  while (std::getline(file, line)) {
    std::smatch match;
    if (std::regex_search(line, match, include_regex)) {
      std::string include_name = match[1].str();

      // Check relative to source file
      auto candidate = source_dir / include_name;
      if (std::filesystem::exists(candidate)) {
        headers.insert(std::filesystem::absolute(candidate).string());
        continue;
      }

      // Check include directories
      for (const auto &dir : include_dirs) {
        candidate = std::filesystem::path(dir) / include_name;
        if (std::filesystem::exists(candidate)) {
          headers.insert(std::filesystem::absolute(candidate).string());
          break;
        }
      }
    }
  }

  return headers;
}

/// @brief Recursively collects all header dependencies.
/// @param source Path to source file.
/// @param include_dirs Include directories.
/// @param visited Already visited files (to avoid cycles).
/// @return Set of all header paths.
inline std::unordered_set<std::string>
CollectAllHeaders(const std::filesystem::path &source,
                  const std::vector<std::string> &include_dirs,
                  std::unordered_set<std::string> &visited) {
  std::unordered_set<std::string> all_headers;
  std::string abs_path = std::filesystem::absolute(source).string();

  if (visited.count(abs_path)) {
    return all_headers;
  }
  visited.insert(abs_path);

  auto direct_headers = ParseIncludes(source, include_dirs);
  for (const auto &header : direct_headers) {
    all_headers.insert(header);
    auto nested = CollectAllHeaders(header, include_dirs, visited);
    all_headers.insert(nested.begin(), nested.end());
  }

  return all_headers;
}

} // namespace detail

/// @namespace sb::platform
/// @brief Platform-specific functionality abstraction.
/// @details Provides a unified interface for operating system operations
///          that differ between Windows and Unix-like systems.
namespace platform {

/// @brief Gets the last modification time of a file.
/// @param path Path to the file.
/// @return Modification time in nanoseconds since epoch, or std::nullopt on
/// error.
inline std::optional<int64_t> GetModTime(const std::filesystem::path &path) {
  std::error_code ec;
  auto ftime = std::filesystem::last_write_time(path, ec);
  if (ec) {
    return std::nullopt;
  }
  auto duration = ftime.time_since_epoch();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
}

/// @brief Checks if a file exists at the given path.
/// @param path Path to check.
/// @return True if the file exists, false otherwise.
inline bool FileExists(const std::filesystem::path &path) {
  std::error_code ec;
  return std::filesystem::exists(path, ec) && !ec;
}

/// @brief Creates a directory and all parent directories.
/// @param path Directory path to create.
/// @return True on success, false on failure.
inline bool CreateDirs(const std::filesystem::path &path) {
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  return !ec;
}

/// @brief Removes a file.
/// @param path Path to the file.
/// @return True on success, false on failure.
inline bool RemoveFile(const std::filesystem::path &path) {
  std::error_code ec;
  return std::filesystem::remove(path, ec) || !ec;
}

#ifdef _WIN32
/// @brief Quotes a command line argument for Windows.
/// @param arg The argument to quote.
/// @return Properly quoted argument.
inline std::string QuoteArgWin(const std::string &arg) {
  if (arg.empty()) {
    return "\"\"";
  }

  bool needs_quote = false;
  for (char c : arg) {
    if (c == ' ' || c == '\t' || c == '"' || c == '\\') {
      needs_quote = true;
      break;
    }
  }

  if (!needs_quote) {
    return arg;
  }

  std::string result = "\"";
  size_t backslashes = 0;

  for (char c : arg) {
    if (c == '\\') {
      ++backslashes;
    } else if (c == '"') {
      result.append(backslashes * 2 + 1, '\\');
      result += '"';
      backslashes = 0;
    } else {
      result.append(backslashes, '\\');
      result += c;
      backslashes = 0;
    }
  }

  result.append(backslashes * 2, '\\');
  result += '"';
  return result;
}

/// @brief Builds a command line string for Windows.
/// @param args Vector of arguments.
/// @return Properly formatted command line string.
inline std::string BuildCommandLineWin(const std::vector<std::string> &args) {
  std::string cmd;
  for (size_t i = 0; i < args.size(); ++i) {
    if (i > 0)
      cmd += ' ';
    cmd += QuoteArgWin(args[i]);
  }
  return cmd;
}
#endif

/// @brief Runs a command synchronously and waits for completion.
/// @param args Command and arguments as a vector of strings.
/// @return Exit code of the command, or -1 on error.
/// @details On Windows, uses CreateProcess. On Unix, uses fork/exec.
inline int RunCommand(const std::vector<std::string> &args) {
  if (args.empty()) {
    return -1;
  }

#ifdef _WIN32
  std::string cmd = BuildCommandLineWin(args);

  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION pi = {};

  // Note: When CreateProcessA fails, no handles are allocated, so no cleanup is
  // needed. SAFETY: const_cast is safe because cmd string lifetime extends
  // beyond CreateProcessA call.
  if (!CreateProcessA(nullptr, const_cast<char *>(cmd.c_str()), nullptr,
                      nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
    return -1;
  }

  WaitForSingleObject(pi.hProcess, INFINITE);

  DWORD exit_code = 0;
  GetExitCodeProcess(pi.hProcess, &exit_code);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  return static_cast<int>(exit_code);
#else
  pid_t pid = fork();
  if (pid == -1) {
    return -1;
  }

  if (pid == 0) {
    // Child process code
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &arg : args) {
      // SAFETY: args vector lifetime extends beyond execvp call.
      // On exec failure, _Exit() immediately terminates the child process,
      // so allocated memory is reclaimed by the OS.
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());
    std::_Exit(127);
  }

  int status;
  if (waitpid(pid, &status, 0) == -1) {
    return -1;
  }

  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return -1;
#endif
}

/// @brief Runs a command asynchronously without waiting.
/// @param args Command and arguments as a vector of strings.
/// @return Process ID/handle of the spawned process, or invalid handle on
/// error.
inline pid_t RunCommandAsync(const std::vector<std::string> &args) {
  if (args.empty()) {
    return SB_INVALID_PID;
  }

#ifdef _WIN32
  std::string cmd = BuildCommandLineWin(args);

  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION pi = {};

  // Note: When CreateProcessA fails, no handles are allocated, so no cleanup is
  // needed. SAFETY: const_cast is safe because cmd string lifetime extends
  // beyond CreateProcessA call.
  if (!CreateProcessA(nullptr, const_cast<char *>(cmd.c_str()), nullptr,
                      nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
    return SB_INVALID_PID;
  }

  CloseHandle(pi.hThread);
  return pi.hProcess;
#else
  pid_t pid = fork();
  if (pid == 0) {
    // Child process code
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &arg : args) {
      // SAFETY: args vector lifetime extends beyond execvp call.
      // On exec failure, _Exit() immediately terminates the child process,
      // so allocated memory is reclaimed by the OS.
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());
    std::_Exit(127);
  }
  return pid;
#endif
}

/// @brief Waits for multiple processes to complete.
/// @param pids Vector of process IDs to wait for.
/// @return True if all processes exited successfully (code 0), false otherwise.
inline bool WaitAll(const std::vector<pid_t> &pids) {
  bool all_ok = true;

#ifdef _WIN32
  // Filter valid handles
  std::vector<HANDLE> valid_handles;
  valid_handles.reserve(pids.size());
  for (HANDLE h : pids) {
    if (h != INVALID_HANDLE_VALUE && h != nullptr) {
      valid_handles.push_back(h);
    }
  }

  if (!valid_handles.empty()) {
    // Wait for all at once (max 64 handles per call)
    size_t offset = 0;
    while (offset < valid_handles.size()) {
      DWORD count = static_cast<DWORD>(std::min(valid_handles.size() - offset,
                                                size_t(MAXIMUM_WAIT_OBJECTS)));
      WaitForMultipleObjects(count, valid_handles.data() + offset, TRUE,
                             INFINITE);
      offset += count;
    }

    // Check exit codes
    for (HANDLE h : valid_handles) {
      DWORD exit_code = 0;
      if (!GetExitCodeProcess(h, &exit_code) || exit_code != 0) {
        all_ok = false;
      }
      CloseHandle(h);
    }
  }
#else
  for (pid_t pid : pids) {
    if (pid <= 0) {
      continue;
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) {
      all_ok = false;
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      all_ok = false;
    }
  }
#endif

  return all_ok;
}

/// @brief Gets the number of available CPU cores.
/// @return Number of CPU cores, minimum 1.
inline int GetCpuCount() {
  int count = static_cast<int>(std::thread::hardware_concurrency());
  return count > 0 ? count : 1;
}

/// @brief Gets the path of the currently running executable.
/// @return Absolute path to the executable, or empty path on error.
inline std::filesystem::path GetExecutablePath() {
#ifdef _WIN32
  wchar_t buf[MAX_PATH];
  DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
  if (len > 0 && len < MAX_PATH) {
    return std::filesystem::path(buf);
  }
  return std::filesystem::path();
#elif defined(__APPLE__)
  char buf[4096];
  uint32_t size = sizeof(buf);
  if (_NSGetExecutablePath(buf, &size) == 0) {
    char real_path[PATH_MAX];
    if (realpath(buf, real_path)) {
      return std::filesystem::path(real_path);
    }
    return std::filesystem::path(buf);
  }
  return std::filesystem::path();
#else
  char buf[4096];
  ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (len != -1) {
    buf[len] = '\0';
    return std::filesystem::path(buf);
  }
  return std::filesystem::path();
#endif
}

/// @brief Replaces the current process with a new executable.
/// @param args Command and arguments for the new process.
/// @note This function does not return on success.
/// @note On Windows, this uses CreateProcess and exit() instead of exec().
inline void Exec(const std::vector<std::string> &args) {
  if (args.empty())
    return;

#ifdef _WIN32
  std::string cmd = BuildCommandLineWin(args);

  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {};

  if (CreateProcessA(nullptr, const_cast<char *>(cmd.c_str()), nullptr, nullptr,
                     TRUE, 0, nullptr, nullptr, &si, &pi)) {
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::exit(static_cast<int>(exit_code));
  }
  std::exit(1);
#else
  std::vector<char *> argv;
  argv.reserve(args.size() + 1);
  for (const auto &arg : args) {
    // SAFETY: args vector lifetime extends beyond execvp call.
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  argv.push_back(nullptr);

  execvp(argv[0], argv.data());
  std::_Exit(127);
#endif
}

/// @brief Runs a command and captures its stdout output.
/// @param cmd Command string to execute.
/// @return Captured stdout with trailing whitespace trimmed.
inline std::string RunCapture(const std::string &cmd) {
  std::string result;
#ifdef _WIN32
  FILE *pipe = _popen(cmd.c_str(), "r");
#else
  FILE *pipe = popen(cmd.c_str(), "r");
#endif
  if (!pipe) {
    return result;
  }

  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result += buffer;
  }

#ifdef _WIN32
  _pclose(pipe);
#else
  pclose(pipe);
#endif

  while (!result.empty() &&
         std::isspace(static_cast<unsigned char>(result.back()))) {
    result.pop_back();
  }
  return result;
}

/// @brief Gets the platform-specific null device for stderr redirection.
/// @return "2>NUL" on Windows, "2>/dev/null" on Unix.
inline const char *GetStderrRedirect() {
#ifdef _WIN32
  return "2>NUL";
#else
  return "2>/dev/null";
#endif
}

/// @brief Gets the executable extension for the current platform.
/// @return ".exe" on Windows, "" on Unix.
inline const char *GetExeExtension() {
#ifdef _WIN32
  return ".exe";
#else
  return "";
#endif
}

/// @brief Gets the static library extension for the current platform.
/// @return ".lib" on Windows, ".a" on Unix.
inline const char *GetStaticLibExtension() {
#ifdef _WIN32
  return ".lib";
#else
  return ".a";
#endif
}

/// @brief Gets the shared library extension for the current platform.
/// @return ".dll" on Windows, ".dylib" on macOS, ".so" on Linux.
inline const char *GetSharedLibExtension() {
#ifdef _WIN32
  return ".dll";
#elif defined(__APPLE__)
  return ".dylib";
#else
  return ".so";
#endif
}

/// @brief Gets the static library prefix for the current platform.
/// @return "" on Windows, "lib" on Unix.
inline const char *GetStaticLibPrefix() {
#ifdef _WIN32
  return "";
#else
  return "lib";
#endif
}

/// @brief Writes a response file for long command lines.
/// @param path Path to response file.
/// @param args Arguments to write.
/// @return True on success.
inline bool WriteResponseFile(const std::filesystem::path &path,
                              const std::vector<std::string> &args) {
  std::ofstream file(path);
  if (!file) {
    return false;
  }
  for (const auto &arg : args) {
    if (arg.find(' ') != std::string::npos ||
        arg.find('"') != std::string::npos) {
      file << '"';
      for (char c : arg) {
        if (c == '"' || c == '\\') {
          file << '\\';
        }
        file << c;
      }
      file << '"';
    } else {
      file << arg;
    }
    file << '\n';
  }
  return file.good();
}

} // namespace platform

/// @class Cache
/// @brief Manages incremental build cache for tracking file changes.
/// @details Stores file hashes in a cache directory to detect which
///          source files have changed and need recompilation.
///
/// The cache stores:
/// - Object files (.o) from previous compilations
/// - A .cache file mapping source paths to content hashes
///
/// @par Cache Directory Structure
/// @code
/// .7b/
/// ├── debug/
/// │   ├── main_a1b2c3d4.o
/// │   ├── utils_e5f6g7h8.o
/// │   └── .cache
/// └── release/
///     ├── main_a1b2c3d4.o
///     ├── utils_e5f6g7h8.o
///     └── .cache
/// @endcode
class Cache {
public:
  /// @brief Creates a cache manager instance.
  /// @param cache_dir Base directory for cache storage.
  /// @param release If true, use release subdirectory; otherwise debug.
  explicit Cache(const std::filesystem::path &cache_dir = SB_CACHE_DIR,
                 bool release = false)
      : cache_dir_(cache_dir),
        obj_dir_(cache_dir / (release ? "release" : "debug")),
        cache_file_(obj_dir_ / ".cache") {}

  /// @brief Initializes the cache directory structure.
  /// @return True on success, false if directory creation failed.
  bool Init() {
    if (!platform::CreateDirs(obj_dir_)) {
      Error("Failed to create cache directory");
      return false;
    }
    Load();
    return true;
  }

  /// @brief Checks if a source file needs to be recompiled.
  /// @param source Path to the source file.
  /// @param include_dirs Include directories for header dependency check.
  /// @return True if recompilation is needed, false if up to date.
  /// @details A file needs rebuild if:
  ///          - Its content hash differs from cached hash
  ///          - Any of its headers have changed
  ///          - Its hash is not in the cache
  ///          - The corresponding object file doesn't exist
  /// @note This function is subject to TOCTOU (time-of-check-time-of-use)
  ///       race conditions if source files are modified during the build.
  ///       This is acceptable for a build system as the next build will
  ///       detect the change.
  bool NeedsRebuild(const std::filesystem::path &source,
                    const std::vector<std::string> &include_dirs) const {
    auto hash = ComputeSourceHash(source, include_dirs);
    if (!hash) {
      return true;
    }

    std::string key = source.string();
    auto it = hashes_.find(key);
    if (it == hashes_.end()) {
      return true;
    }

    if (it->second != *hash) {
      return true;
    }

    auto obj_path = GetObjectPath(source);
    return !platform::FileExists(obj_path);
  }

  /// @brief Gets the object file path for a source file.
  /// @param source Path to the source file.
  /// @return Path where the object file should be stored.
  /// @details Uses a hash of the full source path to avoid collisions
  ///          when multiple source files have the same name.
  std::filesystem::path
  GetObjectPath(const std::filesystem::path &source) const {
    // Hash the full path to ensure uniqueness for files with the same name
    // in different directories (e.g., src/main.cpp and lib/main.cpp)
    std::string path_str = std::filesystem::absolute(source).string();
    uint64_t path_hash = detail::HashString(path_str);
    // Use 12 characters for reduced collision probability
    std::string name = source.stem().string() + "_" +
                       detail::HashToHex(path_hash).substr(0, 12) + ".o";
    return obj_dir_ / name;
  }

  /// @brief Updates the cached hash for a source file.
  /// @param source Path to the source file.
  /// @param include_dirs Include directories.
  /// @details Call this after successfully compiling a source file.
  void Update(const std::filesystem::path &source,
              const std::vector<std::string> &include_dirs) {
    auto hash = ComputeSourceHash(source, include_dirs);
    if (hash) {
      hashes_[source.string()] = *hash;
    }
  }

  /// @brief Marks a source file as part of current build.
  /// @param source Path to the source file.
  void MarkUsed(const std::filesystem::path &source) {
    used_sources_.insert(source.string());
  }

  /// @brief Saves the cache state to disk.
  /// @note Writes to .cache file in the object directory.
  void Save() const {
    std::ofstream file(cache_file_, std::ios::binary);
    if (!file) {
      Warn("Failed to save cache");
      return;
    }

    for (const auto &[path, hash] : hashes_) {
      std::string encoded_path = detail::EncodePathToHex(path);
      file << encoded_path << " " << detail::HashToHex(hash) << "\n";
    }
  }

  /// @brief Removes orphan object files that are no longer needed.
  void CleanOrphans() {
    std::error_code ec;
    for (const auto &entry :
         std::filesystem::directory_iterator(obj_dir_, ec)) {
      if (ec)
        break;
      if (!entry.is_regular_file())
        continue;
      if (entry.path().extension() != ".o")
        continue;

      bool is_orphan = true;
      for (const auto &used : used_sources_) {
        auto obj = GetObjectPath(used);
        std::error_code eq_ec;
        if (std::filesystem::equivalent(entry.path(), obj, eq_ec) && !eq_ec) {
          is_orphan = false;
          break;
        }
      }

      if (is_orphan) {
        Verbose("Removing orphan: " + entry.path().string());
        std::filesystem::remove(entry.path(), ec);
      }
    }
  }

  /// @brief Removes the entire cache directory.
  /// @return True on success, false on failure.
  bool Clean() {
    std::error_code ec;
    std::filesystem::remove_all(cache_dir_, ec);
    hashes_.clear();
    used_sources_.clear();
    return !ec;
  }

  /// @brief Gets the object directory path.
  /// @return Path to object file directory.
  const std::filesystem::path &GetObjDir() const noexcept { return obj_dir_; }

private:
  /// @brief Computes combined hash of source and all its headers.
  /// @param source Source file path.
  /// @param include_dirs Include directories.
  /// @return Combined hash or nullopt on error.
  std::optional<uint64_t>
  ComputeSourceHash(const std::filesystem::path &source,
                    const std::vector<std::string> &include_dirs) const {
    auto source_hash = detail::HashFile(source);
    if (!source_hash) {
      return std::nullopt;
    }

    uint64_t combined = *source_hash;

    std::unordered_set<std::string> visited;
    auto headers = detail::CollectAllHeaders(source, include_dirs, visited);

    // Sort for deterministic ordering
    std::vector<std::string> sorted_headers(headers.begin(), headers.end());
    std::sort(sorted_headers.begin(), sorted_headers.end());

    for (const auto &header : sorted_headers) {
      auto header_hash = detail::HashFile(header);
      if (header_hash) {
        // Improved hash combination using multiplication and XOR
        // This reduces collision probability compared to simple XOR with
        // rotation
        combined += *header_hash;
        combined ^= combined >> 17;
        combined *= 0x9e3779b97f4a7c15ULL; // Golden ratio constant
      }
    }

    return combined;
  }

  /// @brief Loads cache state from disk.
  void Load() {
    std::ifstream file(cache_file_, std::ios::binary);
    if (!file) {
      return;
    }

    std::string line;
    while (std::getline(file, line)) {
      size_t space = line.rfind(' ');
      if (space == std::string::npos || space == 0) {
        continue;
      }

      std::string encoded_path = line.substr(0, space);
      std::string hash_hex = line.substr(space + 1);

      std::string path = detail::DecodeHexToPath(encoded_path);
      if (path.empty()) {
        continue;
      }

      // Validate hash hex string length
      if (hash_hex.length() != 16) {
        continue;
      }

      uint64_t hash = 0;
      bool valid = true;
      for (char c : hash_hex) {
        hash <<= 4;
        if (c >= '0' && c <= '9') {
          hash |= static_cast<uint64_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
          hash |= static_cast<uint64_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
          hash |= static_cast<uint64_t>(c - 'A' + 10);
        } else {
          valid = false;
          break;
        }
      }
      if (valid) {
        hashes_[path] = hash;
      }
    }
  }

  std::filesystem::path cache_dir_;  ///< Base cache directory (.7b)
  std::filesystem::path obj_dir_;    ///< Object file directory
  std::filesystem::path cache_file_; ///< Path to .cache file
  std::unordered_map<std::string, uint64_t>
      hashes_;                                   ///< Source path to hash map
  std::unordered_set<std::string> used_sources_; ///< Currently used sources
};

/// @class Cmd
/// @brief Builder class for constructing and executing shell commands.
/// @details Provides a fluent interface for building command-line invocations
///          with proper argument handling and cross-platform execution.
///
/// @par Example Usage
/// @code{.cpp}
/// sb::Cmd()
///     .Arg("g++")
///     .Args({"-c", "main.cpp", "-o", "main.o"})
///     .Run();
/// @endcode
class Cmd {
public:
  /// @brief Default constructor.
  Cmd() = default;

  /// @brief Adds a single argument to the command.
  /// @param arg The argument to add.
  /// @return Reference to this Cmd for chaining.
  Cmd &Arg(std::string_view arg) {
    args_.emplace_back(arg);
    return *this;
  }

  /// @brief Adds multiple arguments from an initializer list.
  /// @param args The arguments to add.
  /// @return Reference to this Cmd for chaining.
  Cmd &Args(std::initializer_list<std::string_view> args) {
    args_.reserve(args_.size() + args.size());
    for (auto arg : args) {
      args_.emplace_back(arg);
    }
    return *this;
  }

  /// @brief Adds multiple arguments from a vector.
  /// @param args The arguments to add.
  /// @return Reference to this Cmd for chaining.
  Cmd &Args(const std::vector<std::string> &args) {
    args_.reserve(args_.size() + args.size());
    for (const auto &arg : args) {
      args_.push_back(arg);
    }
    return *this;
  }

  /// @brief Runs the command synchronously with verbose logging.
  /// @return True if command exited with code 0, false otherwise.
  bool Run() {
    Verbose("$ " + ToString());
    int code = platform::RunCommand(args_);
    return code == 0;
  }

  /// @brief Runs the command synchronously without logging.
  /// @return True if command exited with code 0, false otherwise.
  bool RunSilent() {
    int code = platform::RunCommand(args_);
    return code == 0;
  }

  /// @brief Runs the command asynchronously.
  /// @return Process ID of the spawned process, or -1 on Windows.
  /// @see platform::WaitAll() to wait for completion.
  pid_t RunAsync() {
    Verbose("$ " + ToString());
    return platform::RunCommandAsync(args_);
  }

  /// @brief Converts the command to a printable string.
  /// @return The full command line with proper quoting.
  std::string ToString() const {
    std::string result;
    for (size_t i = 0; i < args_.size(); ++i) {
      if (i > 0)
        result += " ";
      if (args_[i].find(' ') != std::string::npos ||
          args_[i].find('"') != std::string::npos) {
        result += "\"";
        for (char c : args_[i]) {
          if (c == '"' || c == '\\')
            result += '\\';
          result += c;
        }
        result += "\"";
      } else {
        result += args_[i];
      }
    }
    return result;
  }

  /// @brief Clears all arguments from the command.
  /// @return Reference to this Cmd for chaining.
  Cmd &Clear() {
    args_.clear();
    return *this;
  }

  /// @brief Gets the raw argument vector.
  /// @return Const reference to the internal argument vector.
  const std::vector<std::string> &GetArgs() const noexcept { return args_; }

private:
  std::vector<std::string> args_; ///< Command arguments
};

namespace detail {

/// @struct BuildInfo
/// @brief Stores information about the build executable for self-rebuild.
struct BuildInfo {
  std::filesystem::path executable_path;  ///< Path to current executable
  std::filesystem::path source_path;      ///< Path to build script source
  std::vector<std::string> original_args; ///< Original command line arguments
};

/// @brief Gets the global BuildInfo instance.
/// @return Reference to the static BuildInfo.
inline BuildInfo &GetBuildInfo() {
  static BuildInfo info;
  return info;
}

/// @brief Checks if the build source is newer than the executable.
/// @param info Build information structure.
/// @return True if source is newer and rebuild is needed.
inline bool SourceIsNewer(const BuildInfo &info) {
  auto exe_time = platform::GetModTime(info.executable_path);
  if (!exe_time) {
    return true;
  }

  auto src_time = platform::GetModTime(info.source_path);
  if (src_time && *src_time > *exe_time) {
    return true;
  }

  return false;
}

/// @brief Rebuilds the build executable and re-executes it.
/// @param info Build information structure.
/// @note This function does not return on success.
inline void RebuildAndExec(const BuildInfo &info) {
  Log("Rebuilding build executable...");

  Cmd cmd;
  cmd.Arg(SB_CXX).Arg("-std=c++17").Arg("-O2");
  cmd.Arg(info.source_path.string());
  cmd.Arg("-o").Arg(info.executable_path.string());

#ifndef _WIN32
  // Add pthread support on Unix-like systems
  cmd.Arg("-pthread");
#endif

  if (!cmd.Run()) {
    Error("Failed to rebuild build executable");
    std::exit(1);
  }

  platform::Exec(info.original_args);
}

} // namespace detail

/// @brief Initializes the 7b build system with self-rebuild support.
/// @param argc Argument count from main().
/// @param argv Argument values from main().
/// @param source_file Path to build source file (use __FILE__).
/// @details This function:
///          1. Stores the executable path and command line arguments
///          2. Checks if the build source has been modified
///          3. If modified, recompiles the build executable and re-runs it
///
/// @par Usage
/// Typically called via the SB_INIT macro:
/// @code{.cpp}
/// int main(int argc, char** argv) {
///     SB_INIT(argc, argv);
///     // ...
/// }
/// @endcode
inline void Init(int argc, char **argv, const char *source_file) {
  auto &info = detail::GetBuildInfo();

  info.executable_path = platform::GetExecutablePath();

  info.original_args.reserve(static_cast<size_t>(argc));
  for (int i = 0; i < argc; ++i) {
    info.original_args.push_back(argv[i]);
  }

  if (source_file) {
    info.source_path = source_file;
  }

  if (!info.source_path.empty() && detail::SourceIsNewer(info)) {
    detail::RebuildAndExec(info);
  }
}

/// @class Project
/// @brief Main class for defining and building C++ projects.
/// @details Provides a fluent interface for configuring compilation settings,
///          source files, dependencies, and build options.
///
/// @par Example Usage
/// @code{.cpp}
/// sb::Project("myapp")
///     .Sources({"src/main.cpp", "src/utils.cpp"})
///     .IncludeDir("include")
///     .LinkLib("pthread")
///     .Release()
///     .Build();
/// @endcode
///
/// @par Build Types
/// - Debug (default): Includes debug symbols, no optimization
/// - Release: Optimized, NDEBUG defined
class Project {
public:
  /// @brief Creates a new project with the given name.
  /// @param name Project name (also used as default output name).
  explicit Project(std::string_view name) : name_(name) {}

  /// @brief Adds multiple source files from an initializer list.
  /// @param files Source file paths to add.
  /// @return Reference to this Project for chaining.
  Project &Sources(std::initializer_list<std::string_view> files) {
    sources_.reserve(sources_.size() + files.size());
    for (auto file : files) {
      sources_.emplace_back(file);
    }
    return *this;
  }

  /// @brief Adds multiple source files from a vector.
  /// @param files Source file paths to add.
  /// @return Reference to this Project for chaining.
  Project &Sources(const std::vector<std::string> &files) {
    sources_.reserve(sources_.size() + files.size());
    for (const auto &file : files) {
      sources_.emplace_back(file);
    }
    return *this;
  }

  /// @brief Adds a single source file.
  /// @param file Source file path to add.
  /// @return Reference to this Project for chaining.
  /// @warning Paths containing ".." are rejected to prevent path traversal.
  Project &Source(std::string_view file) {
    // Validate path doesn't contain directory traversal
    if (file.find("..") != std::string_view::npos) {
      Warn("Rejected source with path traversal: " + std::string(file));
      return *this;
    }
    sources_.emplace_back(file);
    return *this;
  }

  /// @brief Adds an include directory (-I flag).
  /// @param dir Include directory path.
  /// @return Reference to this Project for chaining.
  Project &IncludeDir(std::string_view dir) {
    include_dirs_.emplace_back(dir);
    return *this;
  }

  /// @brief Adds multiple include directories.
  /// @param dirs Include directory paths.
  /// @return Reference to this Project for chaining.
  Project &IncludeDirs(std::initializer_list<std::string_view> dirs) {
    include_dirs_.reserve(include_dirs_.size() + dirs.size());
    for (auto dir : dirs) {
      include_dirs_.emplace_back(dir);
    }
    return *this;
  }

  /// @brief Adds a library search path (-L flag).
  /// @param dir Library directory path.
  /// @return Reference to this Project for chaining.
  Project &LibDir(std::string_view dir) {
    lib_dirs_.emplace_back(dir);
    return *this;
  }

  /// @brief Adds multiple library search paths.
  /// @param dirs Library directory paths.
  /// @return Reference to this Project for chaining.
  Project &LibDirs(std::initializer_list<std::string_view> dirs) {
    lib_dirs_.reserve(lib_dirs_.size() + dirs.size());
    for (auto dir : dirs) {
      lib_dirs_.emplace_back(dir);
    }
    return *this;
  }

  /// @brief Adds a preprocessor definition (-D flag).
  /// @param def Definition (e.g., "DEBUG" or "VERSION=1").
  /// @return Reference to this Project for chaining.
  Project &Define(std::string_view def) {
    defines_.emplace_back(def);
    return *this;
  }

  /// @brief Adds multiple preprocessor definitions.
  /// @param defs Definitions to add.
  /// @return Reference to this Project for chaining.
  Project &Defines(std::initializer_list<std::string_view> defs) {
    defines_.reserve(defines_.size() + defs.size());
    for (auto def : defs) {
      defines_.emplace_back(def);
    }
    return *this;
  }

  /// @brief Adds a library to link (-l flag).
  /// @param lib Library name (without lib prefix or extension).
  /// @return Reference to this Project for chaining.
  Project &LinkLib(std::string_view lib) {
    libs_.emplace_back(lib);
    return *this;
  }

  /// @brief Adds multiple libraries to link.
  /// @param libs Library names to link.
  /// @return Reference to this Project for chaining.
  Project &LinkLibs(std::initializer_list<std::string_view> libs) {
    libs_.reserve(libs_.size() + libs.size());
    for (auto lib : libs) {
      libs_.emplace_back(lib);
    }
    return *this;
  }

  /// @brief Links a library statically.
  /// @param lib Library name to link statically.
  /// @return Reference to this Project for chaining.
  /// @details Uses linker flags to force static linking (.a instead of .so).
  /// @note This uses GCC/ld specific flags and may not work on all platforms.
  Project &LinkLibStatic(std::string_view lib) {
    link_flags_.emplace_back("-Wl,-Bstatic");
    link_flags_.emplace_back("-l" + std::string(lib));
    link_flags_.emplace_back("-Wl,-Bdynamic");
    return *this;
  }

  /// @brief Adds a pkg-config package.
  /// @param name Package name as known to pkg-config.
  /// @return Reference to this Project for chaining.
  /// @details Automatically adds --cflags and --libs from pkg-config.
  ///          Shows a warning if the package is not found.
  /// @warning Package names are validated to prevent command injection.
  Project &Pkg(std::string_view name) {
    // Validate package name to prevent command injection
    for (char c : name) {
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' &&
          c != '_' && c != '+' && c != '.') {
        Error("Invalid package name (unsafe characters): " + std::string(name));
        return *this;
      }
    }

    std::string pkg(name);
    std::string stderr_redirect = platform::GetStderrRedirect();

    std::string cflags = platform::RunCapture("pkg-config --cflags " + pkg +
                                              " " + stderr_redirect);
    if (!cflags.empty()) {
      std::istringstream iss(cflags);
      std::string flag;
      while (iss >> flag) {
        cxx_flags_.push_back(flag);
      }
    }

    std::string libs = platform::RunCapture("pkg-config --libs " + pkg + " " +
                                            stderr_redirect);
    if (!libs.empty()) {
      std::istringstream iss(libs);
      std::string flag;
      while (iss >> flag) {
        link_flags_.push_back(flag);
      }
    }

    if (cflags.empty() && libs.empty()) {
      Warn("pkg-config: package '" + pkg + "' not found");
    }

    return *this;
  }

  /// @brief Adds a compiler flag.
  /// @param flag Compiler flag to add.
  /// @return Reference to this Project for chaining.
  Project &CxxFlag(std::string_view flag) {
    cxx_flags_.emplace_back(flag);
    return *this;
  }

  /// @brief Adds multiple compiler flags.
  /// @param flags Compiler flags to add.
  /// @return Reference to this Project for chaining.
  Project &CxxFlags(std::initializer_list<std::string_view> flags) {
    cxx_flags_.reserve(cxx_flags_.size() + flags.size());
    for (auto flag : flags) {
      cxx_flags_.emplace_back(flag);
    }
    return *this;
  }

  /// @brief Adds a linker flag.
  /// @param flag Linker flag to add.
  /// @return Reference to this Project for chaining.
  Project &LinkFlag(std::string_view flag) {
    link_flags_.emplace_back(flag);
    return *this;
  }

  /// @brief Adds multiple linker flags.
  /// @param flags Linker flags to add.
  /// @return Reference to this Project for chaining.
  Project &LinkFlags(std::initializer_list<std::string_view> flags) {
    link_flags_.reserve(link_flags_.size() + flags.size());
    for (auto flag : flags) {
      link_flags_.emplace_back(flag);
    }
    return *this;
  }

  /// @brief Sets the output executable name.
  /// @param name Output file name.
  /// @return Reference to this Project for chaining.
  /// @note If not set, project name is used as output name.
  Project &Output(std::string_view name) {
    output_ = name;
    return *this;
  }

  /// @brief Sets the C++ standard version.
  /// @param std Standard version (e.g., "c++17", "c++20").
  /// @return Reference to this Project for chaining.
  /// @note Default is c++17.
  Project &Standard(std::string_view std) {
    standard_ = std;
    return *this;
  }

  /// @brief Sets the output type.
  /// @param type Output type (Executable, StaticLib, SharedLib).
  /// @return Reference to this Project for chaining.
  Project &Type(OutputType type) {
    output_type_ = type;
    return *this;
  }

  /// @brief Overrides default debug build flags.
  /// @param flags New debug flags.
  /// @return Reference to this Project for chaining.
  Project &DebugFlags(std::initializer_list<std::string_view> flags) {
    debug_flags_.clear();
    debug_flags_.reserve(flags.size());
    for (auto flag : flags) {
      debug_flags_.emplace_back(flag);
    }
    return *this;
  }

  /// @brief Overrides default release build flags.
  /// @param flags New release flags.
  /// @return Reference to this Project for chaining.
  Project &ReleaseFlags(std::initializer_list<std::string_view> flags) {
    release_flags_.clear();
    release_flags_.reserve(flags.size());
    for (auto flag : flags) {
      release_flags_.emplace_back(flag);
    }
    return *this;
  }

  /// @brief Sets the number of parallel compilation jobs.
  /// @param n Number of jobs (0 = auto-detect based on CPU cores).
  /// @return Reference to this Project for chaining.
  Project &Jobs(int n) {
    jobs_ = n;
    return *this;
  }

  /// @brief Enables debug build mode.
  /// @return Reference to this Project for chaining.
  /// @note Debug is the default mode.
  Project &Debug() {
    release_ = false;
    return *this;
  }

  /// @brief Enables release build mode.
  /// @return Reference to this Project for chaining.
  Project &Release() {
    release_ = true;
    return *this;
  }

  /// @brief Builds the project.
  /// @return True on successful build, false on failure.
  /// @details Performs the following steps:
  ///          1. Initializes the build cache
  ///          2. Determines which files need recompilation
  ///          3. Compiles source files in parallel
  ///          4. Links object files into the final executable
  ///          5. Saves the updated cache
  bool Build() {
    if (sources_.empty()) {
      Error("No source files specified");
      return false;
    }

    // Validate source files exist
    for (const auto &source : sources_) {
      if (!platform::FileExists(source)) {
        Error("Source file not found: " + source.string());
        return false;
      }
    }

    Cache cache(SB_CACHE_DIR, release_);
    if (!cache.Init()) {
      return false;
    }

    Log("Building " + name_ + (release_ ? " [release]" : " [debug]") + "...");

    int job_count = jobs_ > 0 ? jobs_ : platform::GetCpuCount();

    struct CompileJob {
      std::filesystem::path source;
      std::filesystem::path obj;
    };
    std::vector<CompileJob> jobs_to_run;
    std::vector<std::filesystem::path> all_objects;

    jobs_to_run.reserve(sources_.size());
    all_objects.reserve(sources_.size());

    for (const auto &source : sources_) {
      cache.MarkUsed(source);
      auto obj_path = cache.GetObjectPath(source);
      all_objects.push_back(obj_path);

      if (!cache.NeedsRebuild(source, include_dirs_)) {
        Verbose("Skipping " + source.string() + " (up to date)");
        continue;
      }

      jobs_to_run.push_back({source, obj_path});
    }

    size_t compiled_count = 0;
    size_t i = 0;

    while (i < jobs_to_run.size()) {
      std::vector<pid_t> pids;
      std::vector<CompileJob *> batch;

      pids.reserve(static_cast<size_t>(job_count));
      batch.reserve(static_cast<size_t>(job_count));

      for (int j = 0; j < job_count && i < jobs_to_run.size(); ++j, ++i) {
        auto &job = jobs_to_run[i];
        Verbose("Compiling " + job.source.string());

        Cmd cmd;
        cmd.Arg(SB_CXX);
        cmd.Arg("-std=" + standard_);

        if (release_) {
          if (release_flags_.empty()) {
            cmd.Args({SB_RELEASE_FLAGS});
          } else {
            cmd.Args(release_flags_);
          }
        } else {
          if (debug_flags_.empty()) {
            cmd.Args({SB_DEBUG_FLAGS});
          } else {
            cmd.Args(debug_flags_);
          }
        }

        // Add -fPIC for shared libraries
        if (output_type_ == OutputType::SharedLib) {
          cmd.Arg("-fPIC");
        }

        for (const auto &inc : include_dirs_) {
          cmd.Arg("-I" + inc);
        }

        for (const auto &def : defines_) {
          cmd.Arg("-D" + def);
        }

        for (const auto &flag : cxx_flags_) {
          cmd.Arg(flag);
        }

        cmd.Args({"-c", job.source.string(), "-o", job.obj.string()});

        pid_t pid = cmd.RunAsync();
        if (pid == SB_INVALID_PID) {
          Error("Failed to start compilation for: " + job.source.string());
          return false;
        }
        pids.push_back(pid);
        batch.push_back(&job);
      }

      bool batch_ok = platform::WaitAll(pids);

      // Update cache for successfully compiled files before checking errors
      if (batch_ok) {
        for (auto *job : batch) {
          cache.Update(job->source, include_dirs_);
          ++compiled_count;
        }
      } else {
        Error("Compilation failed");
        return false;
      }
    }

    // Determine output filename
    std::string output = output_.empty() ? name_ : output_;
    output = ApplyOutputExtension(output);

    bool output_exists = platform::FileExists(output);

    if (compiled_count > 0 || !output_exists) {
      bool link_ok = false;

      switch (output_type_) {
      case OutputType::Executable:
        link_ok = LinkExecutable(output, all_objects, cache);
        break;
      case OutputType::StaticLib:
        link_ok = LinkStaticLib(output, all_objects, cache);
        break;
      case OutputType::SharedLib:
        link_ok = LinkSharedLib(output, all_objects, cache);
        break;
      }

      if (!link_ok) {
        return false;
      }
    }

    cache.CleanOrphans();
    cache.Save();
    Log("Built: " + output + " (" + std::to_string(compiled_count) + "/" +
        std::to_string(sources_.size()) + " compiled)");
    Log("Done!");
    return true;
  }

  /// @brief Cleans the build cache and output files.
  /// @return True on successful clean, false on failure.
  bool Clean() {
    Log("Cleaning " + name_ + "...");

    // Remove output file
    std::string output = output_.empty() ? name_ : output_;
    output = ApplyOutputExtension(output);
    if (platform::FileExists(output)) {
      Verbose("Removing " + output);
      platform::RemoveFile(output);
    }

    Cache cache(SB_CACHE_DIR, release_);
    return cache.Clean();
  }

private:
  /// @brief Applies the correct extension to output filename.
  /// @param name Base output name.
  /// @return Output name with correct extension.
  std::string ApplyOutputExtension(const std::string &name) const {
    std::string result = name;

    switch (output_type_) {
    case OutputType::Executable: {
#ifdef _WIN32
      if (result.length() < 4 || result.substr(result.length() - 4) != ".exe") {
        result += ".exe";
      }
#endif
      break;
    }
    case OutputType::StaticLib: {
      std::string prefix = platform::GetStaticLibPrefix();
      std::string ext = platform::GetStaticLibExtension();
      if (!prefix.empty() && result.substr(0, prefix.length()) != prefix) {
        result = prefix + result;
      }
      if (result.length() < ext.length() ||
          result.substr(result.length() - ext.length()) != ext) {
        result += ext;
      }
      break;
    }
    case OutputType::SharedLib: {
      std::string ext = platform::GetSharedLibExtension();
#ifndef _WIN32
      if (result.substr(0, 3) != "lib") {
        result = "lib" + result;
      }
#endif
      if (result.length() < ext.length() ||
          result.substr(result.length() - ext.length()) != ext) {
        result += ext;
      }
      break;
    }
    }

    return result;
  }

  /// @brief Links an executable.
  /// @param output Output path.
  /// @param objects Object files.
  /// @param cache Build cache.
  /// @return True on success.
  bool LinkExecutable(const std::string &output,
                      const std::vector<std::filesystem::path> &objects,
                      const Cache &cache) {
    Verbose("Linking " + output);

    std::vector<std::string> link_args;
    for (const auto &obj : objects) {
      link_args.push_back(obj.string());
    }

    // Use response file for large projects on Windows
#ifdef _WIN32
    std::filesystem::path rsp_file = cache.GetObjDir() / "link.rsp";
    bool use_rsp = link_args.size() > 50;

    if (use_rsp) {
      if (!platform::WriteResponseFile(rsp_file, link_args)) {
        Warn("Failed to write response file, using direct args");
        use_rsp = false;
      }
    }
#endif

    Cmd cmd;
    cmd.Arg(SB_CXX);

#ifdef _WIN32
    if (use_rsp) {
      cmd.Arg("@" + rsp_file.string());
    } else {
      cmd.Args(link_args);
    }
#else
    (void)cache;
    cmd.Args(link_args);
#endif

    cmd.Arg("-o").Arg(output);

    for (const auto &dir : lib_dirs_) {
      cmd.Arg("-L" + dir);
    }

    for (const auto &flag : link_flags_) {
      cmd.Arg(flag);
    }

    for (const auto &lib : libs_) {
      cmd.Arg("-l" + lib);
    }

    if (!cmd.Run()) {
      Error("Failed to link " + output);
      return false;
    }

    return true;
  }

  /// @brief Creates a static library.
  /// @param output Output path.
  /// @param objects Object files.
  /// @param cache Build cache (unused).
  /// @return True on success.
  bool LinkStaticLib(const std::string &output,
                     const std::vector<std::filesystem::path> &objects,
                     [[maybe_unused]] const Cache &cache) {
    Verbose("Creating static library " + output);

    // Remove existing library first
    platform::RemoveFile(output);

    Cmd cmd;
    cmd.Arg("ar").Arg("rcs").Arg(output);

    for (const auto &obj : objects) {
      cmd.Arg(obj.string());
    }

    if (!cmd.Run()) {
      Error("Failed to create static library " + output);
      return false;
    }

    return true;
  }

  /// @brief Creates a shared library.
  /// @param output Output path.
  /// @param objects Object files.
  /// @param cache Build cache.
  /// @return True on success.
  bool LinkSharedLib(const std::string &output,
                     const std::vector<std::filesystem::path> &objects,
                     [[maybe_unused]] const Cache &cache) {
    Verbose("Creating shared library " + output);

    Cmd cmd;
    cmd.Arg(SB_CXX);
    cmd.Arg("-shared");

#ifdef __APPLE__
    cmd.Arg("-dynamiclib");
#endif

    for (const auto &obj : objects) {
      cmd.Arg(obj.string());
    }

    cmd.Arg("-o").Arg(output);

    for (const auto &dir : lib_dirs_) {
      cmd.Arg("-L" + dir);
    }

    for (const auto &flag : link_flags_) {
      cmd.Arg(flag);
    }

    for (const auto &lib : libs_) {
      cmd.Arg("-l" + lib);
    }

    if (!cmd.Run()) {
      Error("Failed to create shared library " + output);
      return false;
    }

    return true;
  }

  std::string name_;                           ///< Project name
  std::vector<std::filesystem::path> sources_; ///< Source files
  std::vector<std::string> include_dirs_;      ///< Include directories
  std::vector<std::string> lib_dirs_;          ///< Library directories
  std::vector<std::string> defines_;           ///< Preprocessor definitions
  std::vector<std::string> libs_;              ///< Libraries to link
  std::vector<std::string> cxx_flags_;         ///< Compiler flags
  std::vector<std::string> link_flags_;        ///< Linker flags
  std::vector<std::string> debug_flags_;       ///< Custom debug flags
  std::vector<std::string> release_flags_;     ///< Custom release flags
  std::string output_;                         ///< Output file name
  std::string standard_ = "c++17";             ///< C++ standard version
  int jobs_ = 0;                               ///< Parallel job count
  bool release_ = false;                       ///< Release build mode
  OutputType output_type_ = OutputType::Executable; ///< Output type
};

/// @def SB_INIT
/// @brief Initializes 7b with self-rebuild support.
/// @param argc Argument count from main().
/// @param argv Argument values from main().
/// @details Place this macro at the beginning of main() to enable
///          automatic recompilation when the build script changes.
/// @code{.cpp}
/// int main(int argc, char** argv) {
///     SB_INIT(argc, argv);
///     // Build logic here...
///     return 0;
/// }
/// @endcode
#define SB_INIT(argc, argv) sb::Init(argc, argv, __FILE__)

} // namespace sb

#endif // SEVENB_HPP_