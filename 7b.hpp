/// @file 7b.hpp
/// @brief A single-header C++ build system.
/// @author starssxhfdmh
/// @copyright Copyright (c) 2026 starssxhfdmh. MIT License.
/// @version 2.0.1
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
/// - pkg-config integration: Easy dependency management (Unix only)
/// - Cross-platform: Works on Linux, macOS, and Windows
/// - Multi-compiler: Supports GCC, Clang, and MSVC
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
/// 2. Compile: `g++ -std=c++17 build.cpp -o build` (or use cl.exe on Windows)
/// 3. Run: `./build` (or `build.exe` on Windows)
///
/// @par Configuration Macros
/// Define these before including 7b.hpp:
/// | Macro | Description |
/// |-------|-------------|
/// | @c SB_QUIET | Minimal output (errors only) |
/// | @c SB_VERBOSE | Extra detailed output |
/// | @c SB_NO_COLORS | Disable colored output |
/// | @c SB_CXX | Override compiler (auto-detected by default) |
/// | @c SB_CACHE_DIR | Override cache directory (default: .7b) |
/// | @c SB_TOOLCHAIN | Force toolchain: "gcc", "clang", or "msvc" |
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
#include <iomanip>
#include <iostream>
#include <memory>
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
#include <io.h>
#include <windows.h>
/// @brief Windows compatibility typedef for process ID.
typedef HANDLE pid_t;
#define SB_INVALID_PID INVALID_HANDLE_VALUE
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#define SB_INVALID_PID (-1)
#else
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#define SB_INVALID_PID (-1)
#endif

/// @def SB_CACHE_DIR
/// @brief Directory for storing build cache and object files.
/// @details Override by defining before including 7b.hpp.
#ifndef SB_CACHE_DIR
#define SB_CACHE_DIR ".7b"
#endif

/// @namespace sb
/// @brief Main namespace for the 7b build system.
/// @details Contains all classes, functions, and utilities for building C++
/// projects.
namespace sb {

class Cmd;
class Project;
class Toolchain;

/// @enum ToolchainType
/// @brief Supported compiler toolchain types.
enum class ToolchainType {
  GCC,    ///< GNU Compiler Collection
  Clang,  ///< LLVM Clang
  MSVC,   ///< Microsoft Visual C++
  Unknown ///< Unknown or unsupported toolchain
};

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

/// @brief Maximum file size for hashing (100MB).
inline constexpr size_t kMaxHashFileSize = 100 * 1024 * 1024;

/// @brief Progress bar fill character (ASCII fallback available).
inline constexpr const char *kProgressFill = "#";

/// @brief Progress bar empty character.
inline constexpr const char *kProgressEmpty = " ";

/// @brief Arrow character for output (ASCII fallback available).
inline constexpr const char *kArrow = "->";

/// @brief Flag indicating if console supports Unicode.
inline bool g_unicode_supported = false;

/// @brief Flag indicating if console supports ANSI colors.
inline bool g_colors_supported = false;

/// @brief Initializes console capabilities.
inline void InitConsole() {
  static bool initialized = false;
  if (initialized)
    return;
  initialized = true;

#ifdef _WIN32
  // Enable ANSI escape sequences on Windows 10+
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut != INVALID_HANDLE_VALUE) {
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
      mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
      if (SetConsoleMode(hOut, mode)) {
        g_colors_supported = true;
      }
    }
  }
  // Set UTF-8 code page
  if (SetConsoleOutputCP(CP_UTF8)) {
    g_unicode_supported = true;
  }
#else
  // Unix terminals generally support both
  const char *term = std::getenv("TERM");
  if (term && std::strlen(term) > 0) {
    g_colors_supported = true;
    g_unicode_supported = true;
  }
#endif

#ifdef SB_NO_COLORS
  g_colors_supported = false;
#endif
}

/// @brief Gets the color reset code.
/// @return ANSI reset code or empty string if colors disabled.
inline const char *ColorReset() { return g_colors_supported ? "\033[0m" : ""; }

/// @brief Gets the red color code.
/// @return ANSI red code or empty string if colors disabled.
inline const char *ColorRed() { return g_colors_supported ? "\033[31m" : ""; }

/// @brief Gets the green color code.
/// @return ANSI green code or empty string if colors disabled.
inline const char *ColorGreen() { return g_colors_supported ? "\033[32m" : ""; }

/// @brief Gets the yellow color code.
/// @return ANSI yellow code or empty string if colors disabled.
inline const char *ColorYellow() {
  return g_colors_supported ? "\033[33m" : "";
}

/// @brief Gets the cyan color code.
/// @return ANSI cyan code or empty string if colors disabled.
inline const char *ColorCyan() { return g_colors_supported ? "\033[36m" : ""; }

/// @brief Gets the progress bar fill character.
/// @return Unicode block or ASCII # depending on support.
inline const char *GetProgressFill() {
  return g_unicode_supported ? "\xe2\x96\x88" : "#";
}

/// @brief Gets the arrow character.
/// @return Unicode arrow or ASCII -> depending on support.
inline const char *GetArrow() {
  return g_unicode_supported ? "\xe2\x86\x92" : "->";
}

} // namespace detail

/// @brief Logs an error message to stderr.
/// @param msg The error message to display.
/// @note Error messages are always shown regardless of SB_QUIET setting.
inline void Error(std::string_view msg) {
  detail::InitConsole();
  std::cerr << detail::ColorRed() << "[7b] ERROR: " << detail::ColorReset()
            << msg << "\n";
}

/// @brief Logs a warning message to stderr.
/// @param msg The warning message to display.
/// @note Hidden when SB_QUIET is defined.
inline void Warn([[maybe_unused]] std::string_view msg) {
#ifndef SB_QUIET
  detail::InitConsole();
  std::cerr << detail::ColorYellow() << "[7b] WARN: " << detail::ColorReset()
            << msg << "\n";
#endif
}

/// @brief Logs an informational message to stdout.
/// @param msg The info message to display.
/// @note Hidden when SB_QUIET is defined.
inline void Log([[maybe_unused]] std::string_view msg) {
#ifndef SB_QUIET
  detail::InitConsole();
  std::cout << detail::ColorGreen() << "[7b] " << detail::ColorReset() << msg
            << "\n";
#endif
}

/// @brief Logs a verbose debug message to stdout.
/// @param msg The verbose message to display.
/// @note Only shown when SB_VERBOSE is defined.
inline void Verbose([[maybe_unused]] std::string_view msg) {
#ifdef SB_VERBOSE
  detail::InitConsole();
  std::cout << detail::ColorCyan() << "[7b] " << detail::ColorReset() << msg
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

/// @brief Validates a path string for safety.
/// @param path Path string to validate.
/// @return True if path is safe, false if it contains dangerous patterns.
inline bool IsPathSafe(std::string_view path) {
  // Check for directory traversal
  if (path.find("..") != std::string_view::npos) {
    return false;
  }
#ifdef _WIN32
  // Check for Windows-specific dangerous patterns
  if (path.find("::") != std::string_view::npos) {
    return false;
  }
  // Check for device names
  std::string lower(path);
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  const char *devices[] = {"con",  "prn",  "aux",  "nul",  "com1", "com2",
                           "com3", "com4", "lpt1", "lpt2", "lpt3", "lpt4"};
  for (const char *dev : devices) {
    if (lower.find(dev) == 0) {
      size_t len = std::strlen(dev);
      if (lower.length() == len || lower[len] == '.' || lower[len] == '/' ||
          lower[len] == '\\') {
        return false;
      }
    }
  }
#endif
  return true;
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

  static const std::regex include_regex(
      R"(^\s*#\s*include\s*["<]([^">]+)[">])");
  std::string line;
  auto source_dir = source.parent_path();

  while (std::getline(file, line)) {
    std::smatch match;
    if (std::regex_search(line, match, include_regex)) {
      std::string include_name = match[1].str();

      auto candidate = source_dir / include_name;
      if (std::filesystem::exists(candidate)) {
        headers.insert(std::filesystem::absolute(candidate).string());
        continue;
      }

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
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &arg : args) {
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

  if (!CreateProcessA(nullptr, const_cast<char *>(cmd.c_str()), nullptr,
                      nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
    return SB_INVALID_PID;
  }

  CloseHandle(pi.hThread);
  return pi.hProcess;
#else
  pid_t pid = fork();
  if (pid == 0) {
    std::vector<char *> argv;
    argv.reserve(args.size() + 1);
    for (const auto &arg : args) {
      argv.push_back(const_cast<char *>(arg.c_str()));
    }
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());
    std::_Exit(127);
  }
  return pid;
#endif
}

/// @brief Checks if a process has completed (non-blocking).
/// @param pid Process ID to check.
/// @param exit_code Output parameter for exit code if process completed.
/// @return True if process has completed, false if still running.
inline bool IsProcessDone(pid_t pid, int &exit_code) {
#ifdef _WIN32
  if (pid == INVALID_HANDLE_VALUE || pid == nullptr) {
    exit_code = -1;
    return true;
  }
  DWORD result = WaitForSingleObject(pid, 0);
  if (result == WAIT_OBJECT_0) {
    DWORD code = 0;
    GetExitCodeProcess(pid, &code);
    exit_code = static_cast<int>(code);
    return true;
  }
  return false;
#else
  if (pid <= 0) {
    exit_code = -1;
    return true;
  }
  int status;
  pid_t result = waitpid(pid, &status, WNOHANG);
  if (result == pid) {
    if (WIFEXITED(status)) {
      exit_code = WEXITSTATUS(status);
    } else {
      exit_code = -1;
    }
    return true;
  }
  return false;
#endif
}

/// @brief Closes a process handle (Windows only, no-op on Unix).
/// @param pid Process handle to close.
inline void CloseProcessHandle([[maybe_unused]] pid_t pid) {
#ifdef _WIN32
  if (pid != INVALID_HANDLE_VALUE && pid != nullptr) {
    CloseHandle(pid);
  }
#endif
}

/// @brief Waits for all processes with progress callback.
/// @param pids Vector of process IDs.
/// @param on_complete Callback called when each process completes.
/// @return True if all processes exited successfully (code 0).
template <typename Callback>
inline bool WaitAllWithProgress(std::vector<pid_t> &pids,
                                Callback on_complete) {
  bool all_ok = true;
  std::vector<bool> completed(pids.size(), false);
  size_t remaining = pids.size();

  while (remaining > 0) {
    bool any_completed = false;

    for (size_t i = 0; i < pids.size(); ++i) {
      if (completed[i])
        continue;

      int exit_code = 0;
      if (IsProcessDone(pids[i], exit_code)) {
        completed[i] = true;
        --remaining;
        any_completed = true;

        CloseProcessHandle(pids[i]);

        if (exit_code != 0) {
          all_ok = false;
        }

        on_complete(i, exit_code == 0);
      }
    }

    if (!any_completed && remaining > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

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
    argv.push_back(const_cast<char *>(arg.c_str()));
  }
  argv.push_back(nullptr);

  execvp(argv[0], argv.data());
  std::_Exit(127);
#endif
}

/// @brief Runs a command and captures its stdout output.
/// @param args Command arguments (first is the program).
/// @return Captured stdout with trailing whitespace trimmed.
inline std::string RunCapture(const std::vector<std::string> &args) {
  if (args.empty()) {
    return "";
  }

  std::string cmd;
  for (size_t i = 0; i < args.size(); ++i) {
    if (i > 0)
      cmd += ' ';
#ifdef _WIN32
    cmd += QuoteArgWin(args[i]);
#else
    // Simple quoting for shell
    if (args[i].find(' ') != std::string::npos ||
        args[i].find('"') != std::string::npos) {
      cmd += '\'';
      for (char c : args[i]) {
        if (c == '\'')
          cmd += "'\\''";
        else
          cmd += c;
      }
      cmd += '\'';
    } else {
      cmd += args[i];
    }
#endif
  }

  // Redirect stderr to null
#ifdef _WIN32
  cmd += " 2>NUL";
  FILE *pipe = _popen(cmd.c_str(), "r");
#else
  cmd += " 2>/dev/null";
  FILE *pipe = popen(cmd.c_str(), "r");
#endif

  if (!pipe) {
    return "";
  }

  std::string result;
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

/// @brief Gets the terminal width in columns.
/// @return Terminal width, or 80 as fallback.
inline int GetTerminalWidth() {
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO csbi;
  if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
    return csbi.srWindow.Right - csbi.srWindow.Left + 1;
  }
#else
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
    return ws.ws_col;
  }
  // Check COLUMNS environment variable
  const char *cols = std::getenv("COLUMNS");
  if (cols) {
    int width = std::atoi(cols);
    if (width > 0)
      return width;
  }
#endif
  return 80;
}

/// @brief Checks if stdout is a TTY (terminal).
/// @return True if stdout is a terminal, false otherwise.
inline bool IsTty() {
#ifdef _WIN32
  return _isatty(_fileno(stdout)) != 0;
#else
  return isatty(STDOUT_FILENO) != 0;
#endif
}

/// @brief Checks if a command is available in PATH.
/// @param cmd Command name to check.
/// @return True if command exists, false otherwise.
inline bool CommandExists(const std::string &cmd) {
#ifdef _WIN32
  std::string check = "where " + cmd + " >NUL 2>NUL";
  return std::system(check.c_str()) == 0;
#else
  std::string check = "command -v " + cmd + " >/dev/null 2>&1";
  return std::system(check.c_str()) == 0;
#endif
}

} // namespace platform

namespace detail {

/// @class ProgressBar
/// @brief Visual progress indicator for build operations.
/// @details Displays a dynamic progress bar at the current cursor position
///          that adapts to terminal width and shows currently compiling files.
class ProgressBar {
public:
  /// @brief Creates a progress bar.
  /// @param total Total number of items to process.
  explicit ProgressBar(size_t total)
      : total_(total), completed_(0), is_tty_(platform::IsTty()),
        enabled_(is_tty_ && total > 0) {
    InitConsole();
    if (enabled_ && g_colors_supported) {
      std::cout << "\033[?25l" << std::flush;
    }
  }

  /// @brief Destructor, ensures cursor is restored.
  ~ProgressBar() { Finish(); }

  /// @brief Updates the progress bar display.
  /// @param completed Number of completed items.
  /// @param current_files List of currently processing file names.
  void Update(size_t completed, const std::vector<std::string> &current_files) {
    if (!enabled_)
      return;

    completed_ = completed;
    int width = platform::GetTerminalWidth();

    int percent =
        total_ > 0 ? static_cast<int>((completed_ * 100) / total_) : 0;

    std::string files_str;
    for (size_t i = 0; i < current_files.size(); ++i) {
      if (i > 0)
        files_str += ", ";
      auto pos = current_files[i].find_last_of("/\\");
      if (pos != std::string::npos) {
        files_str += current_files[i].substr(pos + 1);
      } else {
        files_str += current_files[i];
      }
    }

    int fixed_chars = 8;
    int max_bar_width = std::min(40, (width - 20) / 2);
    int bar_width = std::max(10, max_bar_width);
    int max_files_width = width - bar_width - fixed_chars - 2;

    if (static_cast<int>(files_str.length()) > max_files_width) {
      if (max_files_width > 3) {
        files_str = files_str.substr(0, max_files_width - 3) + "...";
      } else {
        files_str = "...";
      }
    }

    int filled = (bar_width * static_cast<int>(completed_)) /
                 static_cast<int>(total_ > 0 ? total_ : 1);
    filled = std::min(filled, bar_width);

    std::string bar;
    bar.reserve(bar_width * 3);
    for (int i = 0; i < bar_width; ++i) {
      if (i < filled) {
        bar += GetProgressFill();
      } else {
        bar += " ";
      }
    }

    if (g_colors_supported) {
      std::cout << "\r\033[K";
    } else {
      std::cout << "\r";
      for (int i = 0; i < width - 1; ++i)
        std::cout << ' ';
      std::cout << "\r";
    }

    std::cout << ColorGreen() << bar << ColorCyan() << std::setw(3) << percent
              << "% " << ColorReset() << files_str << std::flush;
  }

  /// @brief Clears the progress bar and restores cursor.
  void Finish() {
    if (!enabled_ || finished_)
      return;

    finished_ = true;
    if (g_colors_supported) {
      std::cout << "\r\033[K\033[?25h" << std::flush;
    } else {
      std::cout << "\r";
      int width = platform::GetTerminalWidth();
      for (int i = 0; i < width - 1; ++i)
        std::cout << ' ';
      std::cout << "\r" << std::flush;
    }
  }

private:
  size_t total_;
  size_t completed_;
  bool is_tty_;
  bool enabled_;
  bool finished_ = false;
};

} // namespace detail

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
  /// @return Process ID of the spawned process.
  /// @see platform::WaitAllWithProgress() to wait for completion.
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
  std::vector<std::string> args_;
};

/// @class Toolchain
/// @brief Abstract base class for compiler toolchains.
/// @details Provides a unified interface for different compilers (GCC, Clang,
/// MSVC).
///          Each toolchain implementation handles compiler-specific flags and
///          commands.
class Toolchain {
public:
  /// @brief Virtual destructor.
  virtual ~Toolchain() = default;

  /// @brief Gets the toolchain type.
  /// @return The type of this toolchain.
  virtual ToolchainType GetType() const = 0;

  /// @brief Gets the toolchain name for display.
  /// @return Human-readable toolchain name.
  virtual std::string GetName() const = 0;

  /// @brief Gets the compiler executable name.
  /// @return Compiler command (e.g., "g++", "clang++", "cl").
  virtual std::string GetCompiler() const = 0;

  /// @brief Gets the archiver executable name.
  /// @return Archiver command (e.g., "ar", "lib").
  virtual std::string GetArchiver() const = 0;

  /// @brief Gets the object file extension.
  /// @return Extension including dot (e.g., ".o", ".obj").
  virtual std::string GetObjectExtension() const = 0;

  /// @brief Gets the executable extension.
  /// @return Extension including dot, or empty for Unix.
  virtual std::string GetExecutableExtension() const = 0;

  /// @brief Gets the static library extension.
  /// @return Extension including dot (e.g., ".a", ".lib").
  virtual std::string GetStaticLibExtension() const = 0;

  /// @brief Gets the shared library extension.
  /// @return Extension including dot (e.g., ".so", ".dll", ".dylib").
  virtual std::string GetSharedLibExtension() const = 0;

  /// @brief Gets the static library prefix.
  /// @return Prefix (e.g., "lib" on Unix, empty on Windows).
  virtual std::string GetStaticLibPrefix() const = 0;

  /// @brief Gets the shared library prefix.
  /// @return Prefix (e.g., "lib" on Unix, empty on Windows).
  virtual std::string GetSharedLibPrefix() const = 0;

  /// @brief Gets default debug compilation flags.
  /// @return Vector of debug flags.
  virtual std::vector<std::string> GetDebugFlags() const = 0;

  /// @brief Gets default release compilation flags.
  /// @return Vector of release flags.
  virtual std::vector<std::string> GetReleaseFlags() const = 0;

  /// @brief Checks if this toolchain supports pkg-config.
  /// @return True if pkg-config is supported.
  virtual bool SupportsPkgConfig() const = 0;

  /// @brief Checks if this toolchain supports static linking control.
  /// @return True if static linking flags are supported.
  virtual bool SupportsStaticLinking() const = 0;

  /// @brief Builds a compile command for a single source file.
  /// @param source Source file path.
  /// @param output Object file path.
  /// @param standard C++ standard (e.g., "c++17").
  /// @param flags Additional compiler flags.
  /// @param includes Include directories.
  /// @param defines Preprocessor definitions.
  /// @param is_shared True if building for shared library.
  /// @return Cmd object ready to execute.
  virtual Cmd BuildCompileCommand(const std::string &source,
                                  const std::string &output,
                                  const std::string &standard,
                                  const std::vector<std::string> &flags,
                                  const std::vector<std::string> &includes,
                                  const std::vector<std::string> &defines,
                                  bool is_shared) const = 0;

  /// @brief Builds a link command for an executable.
  /// @param output Output file path.
  /// @param objects Object files to link.
  /// @param lib_dirs Library search directories.
  /// @param libs Libraries to link.
  /// @param flags Additional linker flags.
  /// @return Cmd object ready to execute.
  virtual Cmd BuildLinkCommand(const std::string &output,
                               const std::vector<std::string> &objects,
                               const std::vector<std::string> &lib_dirs,
                               const std::vector<std::string> &libs,
                               const std::vector<std::string> &flags) const = 0;

  /// @brief Builds a command to create a static library.
  /// @param output Output library path.
  /// @param objects Object files to archive.
  /// @return Cmd object ready to execute.
  virtual Cmd
  BuildStaticLibCommand(const std::string &output,
                        const std::vector<std::string> &objects) const = 0;

  /// @brief Builds a command to create a shared library.
  /// @param output Output library path.
  /// @param objects Object files to link.
  /// @param lib_dirs Library search directories.
  /// @param libs Libraries to link.
  /// @param flags Additional linker flags.
  /// @return Cmd object ready to execute.
  virtual Cmd
  BuildSharedLibCommand(const std::string &output,
                        const std::vector<std::string> &objects,
                        const std::vector<std::string> &lib_dirs,
                        const std::vector<std::string> &libs,
                        const std::vector<std::string> &flags) const = 0;

  /// @brief Gets flags for static library linking.
  /// @param lib Library name.
  /// @return Vector of flags, or empty if not supported.
  virtual std::vector<std::string>
  GetStaticLinkFlags(const std::string &lib) const = 0;

  /// @brief Creates the appropriate toolchain for the current platform.
  /// @return Unique pointer to the detected toolchain.
  static std::unique_ptr<Toolchain> Detect();

  /// @brief Creates a specific toolchain by type.
  /// @param type The toolchain type to create.
  /// @return Unique pointer to the toolchain, or nullptr if unavailable.
  static std::unique_ptr<Toolchain> Create(ToolchainType type);
};

/// @class GCCToolchain
/// @brief GCC compiler toolchain implementation.
class GCCToolchain : public Toolchain {
public:
  ToolchainType GetType() const override { return ToolchainType::GCC; }
  std::string GetName() const override { return "GCC"; }
  std::string GetCompiler() const override { return "g++"; }
  std::string GetArchiver() const override { return "ar"; }
  std::string GetObjectExtension() const override { return ".o"; }
  std::string GetStaticLibExtension() const override { return ".a"; }
  std::string GetStaticLibPrefix() const override { return "lib"; }
  std::string GetSharedLibPrefix() const override { return "lib"; }
  bool SupportsPkgConfig() const override { return true; }
  bool SupportsStaticLinking() const override { return true; }

  std::string GetExecutableExtension() const override {
#ifdef _WIN32
    return ".exe";
#else
    return "";
#endif
  }

  std::string GetSharedLibExtension() const override {
#ifdef __APPLE__
    return ".dylib";
#elif defined(_WIN32)
    return ".dll";
#else
    return ".so";
#endif
  }

  std::vector<std::string> GetDebugFlags() const override {
    return {"-g", "-O0", "-Wall", "-Wextra"};
  }

  std::vector<std::string> GetReleaseFlags() const override {
    return {"-O2", "-DNDEBUG", "-Wall"};
  }

  Cmd BuildCompileCommand(const std::string &source, const std::string &output,
                          const std::string &standard,
                          const std::vector<std::string> &flags,
                          const std::vector<std::string> &includes,
                          const std::vector<std::string> &defines,
                          bool is_shared) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("-std=" + standard);
    cmd.Args(flags);

    if (is_shared) {
      cmd.Arg("-fPIC");
    }

    for (const auto &inc : includes) {
      cmd.Arg("-I" + inc);
    }
    for (const auto &def : defines) {
      cmd.Arg("-D" + def);
    }

    cmd.Args({"-c", source, "-o", output});
    return cmd;
  }

  Cmd BuildLinkCommand(const std::string &output,
                       const std::vector<std::string> &objects,
                       const std::vector<std::string> &lib_dirs,
                       const std::vector<std::string> &libs,
                       const std::vector<std::string> &flags) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Args(objects);
    cmd.Args({"-o", output});

    for (const auto &dir : lib_dirs) {
      cmd.Arg("-L" + dir);
    }
    cmd.Args(flags);
    for (const auto &lib : libs) {
      cmd.Arg("-l" + lib);
    }

    return cmd;
  }

  Cmd BuildStaticLibCommand(
      const std::string &output,
      const std::vector<std::string> &objects) const override {
    Cmd cmd;
    cmd.Arg(GetArchiver());
    cmd.Args({"rcs", output});
    cmd.Args(objects);
    return cmd;
  }

  Cmd BuildSharedLibCommand(
      const std::string &output, const std::vector<std::string> &objects,
      const std::vector<std::string> &lib_dirs,
      const std::vector<std::string> &libs,
      const std::vector<std::string> &flags) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("-shared");
    cmd.Args(objects);
    cmd.Args({"-o", output});

    for (const auto &dir : lib_dirs) {
      cmd.Arg("-L" + dir);
    }
    cmd.Args(flags);
    for (const auto &lib : libs) {
      cmd.Arg("-l" + lib);
    }

    return cmd;
  }

  std::vector<std::string>
  GetStaticLinkFlags(const std::string &lib) const override {
    return {"-Wl,-Bstatic", "-l" + lib, "-Wl,-Bdynamic"};
  }
};

/// @class ClangToolchain
/// @brief Clang compiler toolchain implementation.
class ClangToolchain : public Toolchain {
public:
  ToolchainType GetType() const override { return ToolchainType::Clang; }
  std::string GetName() const override { return "Clang"; }
  std::string GetCompiler() const override { return "clang++"; }
  std::string GetArchiver() const override { return "ar"; }
  std::string GetObjectExtension() const override { return ".o"; }
  std::string GetStaticLibExtension() const override { return ".a"; }
  std::string GetStaticLibPrefix() const override { return "lib"; }
  std::string GetSharedLibPrefix() const override { return "lib"; }
  bool SupportsPkgConfig() const override { return true; }

  bool SupportsStaticLinking() const override {
#ifdef __APPLE__
    return false; // macOS doesn't support -Bstatic/-Bdynamic
#else
    return true;
#endif
  }

  std::string GetExecutableExtension() const override {
#ifdef _WIN32
    return ".exe";
#else
    return "";
#endif
  }

  std::string GetSharedLibExtension() const override {
#ifdef __APPLE__
    return ".dylib";
#elif defined(_WIN32)
    return ".dll";
#else
    return ".so";
#endif
  }

  std::vector<std::string> GetDebugFlags() const override {
    return {"-g", "-O0", "-Wall", "-Wextra"};
  }

  std::vector<std::string> GetReleaseFlags() const override {
    return {"-O2", "-DNDEBUG", "-Wall"};
  }

  Cmd BuildCompileCommand(const std::string &source, const std::string &output,
                          const std::string &standard,
                          const std::vector<std::string> &flags,
                          const std::vector<std::string> &includes,
                          const std::vector<std::string> &defines,
                          bool is_shared) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("-std=" + standard);
    cmd.Args(flags);

    if (is_shared) {
      cmd.Arg("-fPIC");
    }

    for (const auto &inc : includes) {
      cmd.Arg("-I" + inc);
    }
    for (const auto &def : defines) {
      cmd.Arg("-D" + def);
    }

    cmd.Args({"-c", source, "-o", output});
    return cmd;
  }

  Cmd BuildLinkCommand(const std::string &output,
                       const std::vector<std::string> &objects,
                       const std::vector<std::string> &lib_dirs,
                       const std::vector<std::string> &libs,
                       const std::vector<std::string> &flags) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Args(objects);
    cmd.Args({"-o", output});

    for (const auto &dir : lib_dirs) {
      cmd.Arg("-L" + dir);
    }
    cmd.Args(flags);
    for (const auto &lib : libs) {
      cmd.Arg("-l" + lib);
    }

    return cmd;
  }

  Cmd BuildStaticLibCommand(
      const std::string &output,
      const std::vector<std::string> &objects) const override {
    Cmd cmd;
    cmd.Arg(GetArchiver());
    cmd.Args({"rcs", output});
    cmd.Args(objects);
    return cmd;
  }

  Cmd BuildSharedLibCommand(
      const std::string &output, const std::vector<std::string> &objects,
      const std::vector<std::string> &lib_dirs,
      const std::vector<std::string> &libs,
      const std::vector<std::string> &flags) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("-shared");
    cmd.Args(objects);
    cmd.Args({"-o", output});

    for (const auto &dir : lib_dirs) {
      cmd.Arg("-L" + dir);
    }
    cmd.Args(flags);
    for (const auto &lib : libs) {
      cmd.Arg("-l" + lib);
    }

    return cmd;
  }

  std::vector<std::string>
  GetStaticLinkFlags(const std::string &lib) const override {
#ifdef __APPLE__
    // macOS: use full path to static library instead
    Warn("Static linking with -Bstatic not supported on macOS. "
         "Use full library path instead.");
    return {"-l" + lib};
#else
    return {"-Wl,-Bstatic", "-l" + lib, "-Wl,-Bdynamic"};
#endif
  }
};

/// @class MSVCToolchain
/// @brief Microsoft Visual C++ compiler toolchain implementation.
class MSVCToolchain : public Toolchain {
public:
  ToolchainType GetType() const override { return ToolchainType::MSVC; }
  std::string GetName() const override { return "MSVC"; }
  std::string GetCompiler() const override { return "cl"; }
  std::string GetArchiver() const override { return "lib"; }
  std::string GetObjectExtension() const override { return ".obj"; }
  std::string GetExecutableExtension() const override { return ".exe"; }
  std::string GetStaticLibExtension() const override { return ".lib"; }
  std::string GetSharedLibExtension() const override { return ".dll"; }
  std::string GetStaticLibPrefix() const override { return ""; }
  std::string GetSharedLibPrefix() const override { return ""; }
  bool SupportsPkgConfig() const override { return false; }
  bool SupportsStaticLinking() const override { return false; }

  std::vector<std::string> GetDebugFlags() const override {
    return {"/Zi", "/Od", "/W4", "/EHsc", "/MDd"};
  }

  std::vector<std::string> GetReleaseFlags() const override {
    return {"/O2", "/DNDEBUG", "/W4", "/EHsc", "/MD"};
  }

  Cmd BuildCompileCommand(const std::string &source, const std::string &output,
                          const std::string &standard,
                          const std::vector<std::string> &flags,
                          const std::vector<std::string> &includes,
                          const std::vector<std::string> &defines,
                          [[maybe_unused]] bool is_shared) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("/nologo");
    cmd.Arg("/std:" + standard);
    cmd.Args(flags);

    for (const auto &inc : includes) {
      cmd.Arg("/I" + inc);
    }
    for (const auto &def : defines) {
      cmd.Arg("/D" + def);
    }

    cmd.Arg("/c");
    cmd.Arg(source);
    cmd.Arg("/Fo" + output);

    return cmd;
  }

  Cmd BuildLinkCommand(const std::string &output,
                       const std::vector<std::string> &objects,
                       const std::vector<std::string> &lib_dirs,
                       const std::vector<std::string> &libs,
                       const std::vector<std::string> &flags) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("/nologo");
    cmd.Args(objects);
    cmd.Arg("/Fe" + output);
    cmd.Arg("/link");

    for (const auto &dir : lib_dirs) {
      cmd.Arg("/LIBPATH:" + dir);
    }
    cmd.Args(flags);
    for (const auto &lib : libs) {
      // MSVC expects library.lib format
      if (lib.find(".lib") == std::string::npos) {
        cmd.Arg(lib + ".lib");
      } else {
        cmd.Arg(lib);
      }
    }

    return cmd;
  }

  Cmd BuildStaticLibCommand(
      const std::string &output,
      const std::vector<std::string> &objects) const override {
    Cmd cmd;
    cmd.Arg(GetArchiver());
    cmd.Arg("/nologo");
    cmd.Arg("/OUT:" + output);
    cmd.Args(objects);
    return cmd;
  }

  Cmd BuildSharedLibCommand(
      const std::string &output, const std::vector<std::string> &objects,
      const std::vector<std::string> &lib_dirs,
      const std::vector<std::string> &libs,
      const std::vector<std::string> &flags) const override {
    Cmd cmd;
    cmd.Arg(GetCompiler());
    cmd.Arg("/nologo");
    cmd.Arg("/LD");
    cmd.Args(objects);
    cmd.Arg("/Fe" + output);
    cmd.Arg("/link");

    for (const auto &dir : lib_dirs) {
      cmd.Arg("/LIBPATH:" + dir);
    }
    cmd.Args(flags);
    for (const auto &lib : libs) {
      if (lib.find(".lib") == std::string::npos) {
        cmd.Arg(lib + ".lib");
      } else {
        cmd.Arg(lib);
      }
    }

    return cmd;
  }

  std::vector<std::string>
  GetStaticLinkFlags([[maybe_unused]] const std::string &lib) const override {
    Warn("LinkLibStatic is not supported on MSVC. "
         "Use full path to .lib file instead.");
    return {};
  }
};

/// @brief Detects and creates the appropriate toolchain.
/// @return Unique pointer to the detected toolchain.
inline std::unique_ptr<Toolchain> Toolchain::Detect() {
#ifdef SB_TOOLCHAIN
  std::string forced = SB_TOOLCHAIN;
  if (forced == "gcc")
    return std::make_unique<GCCToolchain>();
  if (forced == "clang")
    return std::make_unique<ClangToolchain>();
  if (forced == "msvc")
    return std::make_unique<MSVCToolchain>();
#endif

#ifdef SB_CXX
  std::string compiler = SB_CXX;
  if (compiler.find("g++") != std::string::npos ||
      compiler.find("gcc") != std::string::npos) {
    return std::make_unique<GCCToolchain>();
  }
  if (compiler.find("clang") != std::string::npos) {
    return std::make_unique<ClangToolchain>();
  }
  if (compiler.find("cl") != std::string::npos) {
    return std::make_unique<MSVCToolchain>();
  }
#endif

#ifdef _WIN32
  // On Windows, prefer MSVC if available, then Clang, then GCC
  if (platform::CommandExists("cl")) {
    return std::make_unique<MSVCToolchain>();
  }
  if (platform::CommandExists("clang++")) {
    return std::make_unique<ClangToolchain>();
  }
  if (platform::CommandExists("g++")) {
    return std::make_unique<GCCToolchain>();
  }
#else
  // On Unix, prefer Clang if available, then GCC
  if (platform::CommandExists("clang++")) {
    return std::make_unique<ClangToolchain>();
  }
  if (platform::CommandExists("g++")) {
    return std::make_unique<GCCToolchain>();
  }
#endif

  // Fallback to GCC
  Warn("Could not detect compiler, falling back to g++");
  return std::make_unique<GCCToolchain>();
}

/// @brief Creates a specific toolchain by type.
/// @param type The toolchain type to create.
/// @return Unique pointer to the toolchain.
inline std::unique_ptr<Toolchain> Toolchain::Create(ToolchainType type) {
  switch (type) {
  case ToolchainType::GCC:
    return std::make_unique<GCCToolchain>();
  case ToolchainType::Clang:
    return std::make_unique<ClangToolchain>();
  case ToolchainType::MSVC:
    return std::make_unique<MSVCToolchain>();
  default:
    return Detect();
  }
}

/// @class Cache
/// @brief Manages incremental build cache for tracking file changes.
/// @details Stores file hashes in a cache directory to detect which
///          source files have changed and need recompilation.
///
/// The cache stores:
/// - Object files from previous compilations
/// - A .cache file mapping source paths to content hashes
/// - Configuration hash to detect flag changes
class Cache {
public:
  /// @brief Creates a cache manager instance.
  /// @param cache_dir Base directory for cache storage.
  /// @param release If true, use release subdirectory; otherwise debug.
  /// @param toolchain Pointer to the toolchain for object extension.
  explicit Cache(const std::filesystem::path &cache_dir, bool release,
                 const Toolchain *toolchain)
      : cache_dir_(cache_dir),
        obj_dir_(cache_dir / (release ? "release" : "debug")),
        cache_file_(obj_dir_ / ".cache"), config_file_(obj_dir_ / ".config"),
        toolchain_(toolchain) {}

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

  /// @brief Sets the configuration hash for change detection.
  /// @param config_hash Hash of build configuration.
  void SetConfigHash(uint64_t config_hash) {
    uint64_t old_hash = LoadConfigHash();
    if (old_hash != config_hash) {
      Verbose("Build configuration changed, full rebuild needed");
      hashes_.clear();
      SaveConfigHash(config_hash);
    }
  }

  /// @brief Checks if a source file needs to be recompiled.
  /// @param source Path to the source file.
  /// @param include_dirs Include directories for header dependency check.
  /// @return True if recompilation is needed, false if up to date.
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
  std::filesystem::path
  GetObjectPath(const std::filesystem::path &source) const {
    std::string path_str = std::filesystem::absolute(source).string();
    uint64_t path_hash = detail::HashString(path_str);
    std::string ext = toolchain_ ? toolchain_->GetObjectExtension() : ".o";
    std::string name =
        source.stem().string() + "_" + detail::HashToHex(path_hash) + ext;
    return obj_dir_ / name;
  }

  /// @brief Updates the cached hash for a source file.
  /// @param source Path to the source file.
  /// @param include_dirs Include directories.
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
    std::string obj_ext = toolchain_ ? toolchain_->GetObjectExtension() : ".o";

    for (const auto &entry :
         std::filesystem::directory_iterator(obj_dir_, ec)) {
      if (ec)
        break;
      if (!entry.is_regular_file())
        continue;
      if (entry.path().extension() != obj_ext)
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

    std::vector<std::string> sorted_headers(headers.begin(), headers.end());
    std::sort(sorted_headers.begin(), sorted_headers.end());

    for (const auto &header : sorted_headers) {
      auto header_hash = detail::HashFile(header);
      if (header_hash) {
        combined += *header_hash;
        combined ^= combined >> 17;
        combined *= 0x9e3779b97f4a7c15ULL;
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

  /// @brief Loads the configuration hash from disk.
  /// @return The stored hash, or 0 if not found.
  uint64_t LoadConfigHash() const {
    std::ifstream file(config_file_);
    if (!file)
      return 0;

    std::string line;
    if (std::getline(file, line) && line.length() == 16) {
      uint64_t hash = 0;
      for (char c : line) {
        hash <<= 4;
        if (c >= '0' && c <= '9')
          hash |= static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
          hash |= static_cast<uint64_t>(c - 'a' + 10);
        else
          return 0;
      }
      return hash;
    }
    return 0;
  }

  /// @brief Saves the configuration hash to disk.
  /// @param hash The hash to save.
  void SaveConfigHash(uint64_t hash) const {
    std::ofstream file(config_file_);
    if (file) {
      file << detail::HashToHex(hash) << "\n";
    }
  }

  std::filesystem::path cache_dir_;
  std::filesystem::path obj_dir_;
  std::filesystem::path cache_file_;
  std::filesystem::path config_file_;
  const Toolchain *toolchain_;
  std::unordered_map<std::string, uint64_t> hashes_;
  std::unordered_set<std::string> used_sources_;
};

namespace detail {

/// @struct BuildInfo
/// @brief Stores information about the build executable for self-rebuild.
struct BuildInfo {
  std::filesystem::path executable_path;
  std::filesystem::path source_path;
  std::vector<std::string> original_args;
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

#ifdef _WIN32
  // Windows locks running executables, minimizing the chance of successful
  // overwrite. We rename the current executable to allow the new one to be
  // written.
  std::filesystem::path old_exe = info.executable_path;
  old_exe += ".old";
  std::error_code ec;
  if (std::filesystem::exists(old_exe, ec)) {
    std::filesystem::remove(old_exe, ec);
  }
  std::filesystem::rename(info.executable_path, old_exe, ec);
  if (ec) {
    Verbose("Failed to rename running executable: " + ec.message());
  }
#endif

  auto toolchain = Toolchain::Detect();

  Cmd cmd;
  cmd.Arg(toolchain->GetCompiler());

  if (toolchain->GetType() == ToolchainType::MSVC) {
    cmd.Args({"/nologo", "/std:c++17", "/O2", "/EHsc"});
    cmd.Arg(info.source_path.string());
    cmd.Arg("/Fe" + info.executable_path.string());
  } else {
    cmd.Args({"-std=c++17", "-O2"});
    cmd.Arg(info.source_path.string());
    cmd.Args({"-o", info.executable_path.string()});
#ifndef _WIN32
    cmd.Arg("-pthread");
#endif
  }

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
inline void Init(int argc, char **argv, const char *source_file) {
  detail::InitConsole();

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
class Project {
public:
  /// @brief Creates a new project with the given name.
  /// @param name Project name (also used as default output name).
  explicit Project(std::string_view name)
      : name_(name), toolchain_(Toolchain::Detect()) {}

  /// @brief Creates a project with a specific toolchain.
  /// @param name Project name.
  /// @param type Toolchain type to use.
  Project(std::string_view name, ToolchainType type)
      : name_(name), toolchain_(Toolchain::Create(type)) {}

  /// @brief Adds multiple source files from an initializer list.
  /// @param files Source file paths to add.
  /// @return Reference to this Project for chaining.
  Project &Sources(std::initializer_list<std::string_view> files) {
    sources_.reserve(sources_.size() + files.size());
    for (auto file : files) {
      if (!detail::IsPathSafe(file)) {
        Warn("Rejected source with unsafe path: " + std::string(file));
        continue;
      }
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
      if (!detail::IsPathSafe(file)) {
        Warn("Rejected source with unsafe path: " + file);
        continue;
      }
      sources_.emplace_back(file);
    }
    return *this;
  }

  /// @brief Adds a single source file.
  /// @param file Source file path to add.
  /// @return Reference to this Project for chaining.
  Project &Source(std::string_view file) {
    if (!detail::IsPathSafe(file)) {
      Warn("Rejected source with unsafe path: " + std::string(file));
      return *this;
    }
    sources_.emplace_back(file);
    return *this;
  }

  /// @brief Adds an include directory (-I flag).
  /// @param dir Include directory path.
  /// @return Reference to this Project for chaining.
  Project &IncludeDir(std::string_view dir) {
    if (!detail::IsPathSafe(dir)) {
      Warn("Rejected include dir with unsafe path: " + std::string(dir));
      return *this;
    }
    include_dirs_.emplace_back(dir);
    return *this;
  }

  /// @brief Adds multiple include directories.
  /// @param dirs Include directory paths.
  /// @return Reference to this Project for chaining.
  Project &IncludeDirs(std::initializer_list<std::string_view> dirs) {
    include_dirs_.reserve(include_dirs_.size() + dirs.size());
    for (auto dir : dirs) {
      if (!detail::IsPathSafe(dir)) {
        Warn("Rejected include dir with unsafe path: " + std::string(dir));
        continue;
      }
      include_dirs_.emplace_back(dir);
    }
    return *this;
  }

  /// @brief Adds a library search path (-L flag).
  /// @param dir Library directory path.
  /// @return Reference to this Project for chaining.
  Project &LibDir(std::string_view dir) {
    if (!detail::IsPathSafe(dir)) {
      Warn("Rejected lib dir with unsafe path: " + std::string(dir));
      return *this;
    }
    lib_dirs_.emplace_back(dir);
    return *this;
  }

  /// @brief Adds multiple library search paths.
  /// @param dirs Library directory paths.
  /// @return Reference to this Project for chaining.
  Project &LibDirs(std::initializer_list<std::string_view> dirs) {
    lib_dirs_.reserve(lib_dirs_.size() + dirs.size());
    for (auto dir : dirs) {
      if (!detail::IsPathSafe(dir)) {
        Warn("Rejected lib dir with unsafe path: " + std::string(dir));
        continue;
      }
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

  /// @brief Links a library statically (GCC only, Linux only).
  /// @param lib Library name to link statically.
  /// @return Reference to this Project for chaining.
  /// @details This only works on GCC/Linux. On macOS and MSVC, use full
  ///          library path instead.
  /// @note Shows a warning if the toolchain doesn't support static linking.
  Project &LinkLibStatic(std::string_view lib) {
    if (!toolchain_->SupportsStaticLinking()) {
      Warn("Static linking not supported on " + toolchain_->GetName() +
           ". Use full library path instead.");
      libs_.emplace_back(lib);
      return *this;
    }

    auto flags = toolchain_->GetStaticLinkFlags(std::string(lib));
    for (const auto &flag : flags) {
      link_flags_.push_back(flag);
    }
    return *this;
  }

  /// @brief Adds a pkg-config package (Unix only).
  /// @param name Package name as known to pkg-config.
  /// @return Reference to this Project for chaining.
  /// @details On Windows/MSVC, this is a no-op with a warning.
  Project &Pkg(std::string_view name) {
    if (!toolchain_->SupportsPkgConfig()) {
      Warn("pkg-config not supported on " + toolchain_->GetName());
      return *this;
    }

    // Validate package name
    for (char c : name) {
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' &&
          c != '_' && c != '+' && c != '.') {
        Error("Invalid package name (unsafe characters): " + std::string(name));
        return *this;
      }
    }

    std::string pkg(name);

    std::string cflags = platform::RunCapture({"pkg-config", "--cflags", pkg});
    if (!cflags.empty()) {
      std::istringstream iss(cflags);
      std::string flag;
      while (iss >> flag) {
        cxx_flags_.push_back(flag);
      }
    }

    std::string libs = platform::RunCapture({"pkg-config", "--libs", pkg});
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
  Project &Output(std::string_view name) {
    output_ = name;
    return *this;
  }

  /// @brief Sets the C++ standard version.
  /// @param std Standard version (e.g., "c++17", "c++20").
  /// @return Reference to this Project for chaining.
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

  /// @brief Sets a specific toolchain type.
  /// @param type The toolchain type to use.
  /// @return Reference to this Project for chaining.
  Project &UseToolchain(ToolchainType type) {
    toolchain_ = Toolchain::Create(type);
    return *this;
  }

  /// @brief Gets the current toolchain.
  /// @return Pointer to the current toolchain.
  const Toolchain *GetToolchain() const { return toolchain_.get(); }

  /// @brief Generates compile_commands.json for IDE/clangd support.
  /// @param output_path Path to write the JSON file.
  /// @return Reference to this Project for chaining.
  Project &GenerateCompileCommands(
      const std::filesystem::path &output_path = "compile_commands.json") {
    if (sources_.empty()) {
      Warn("No sources to generate compile_commands.json");
      return *this;
    }

    std::ofstream file(output_path);
    if (!file) {
      Error("Failed to create compile_commands.json");
      return *this;
    }

    std::filesystem::path cwd = std::filesystem::current_path();
    std::string cwd_str = cwd.string();

    file << "[\n";

    auto build_flags =
        release_ ? (release_flags_.empty() ? toolchain_->GetReleaseFlags()
                                           : release_flags_)
                 : (debug_flags_.empty() ? toolchain_->GetDebugFlags()
                                         : debug_flags_);

    for (size_t idx = 0; idx < sources_.size(); ++idx) {
      const auto &source = sources_[idx];
      std::filesystem::path abs_source = std::filesystem::absolute(source);

      std::string command = toolchain_->GetCompiler();

      if (toolchain_->GetType() == ToolchainType::MSVC) {
        command += " /std:" + standard_;
      } else {
        command += " -std=" + standard_;
      }

      for (const auto &flag : build_flags) {
        command += " " + flag;
      }

      for (const auto &inc : include_dirs_) {
        std::filesystem::path abs_inc = std::filesystem::absolute(inc);
        if (toolchain_->GetType() == ToolchainType::MSVC) {
          command += " /I" + abs_inc.string();
        } else {
          command += " -I" + abs_inc.string();
        }
      }

      for (const auto &def : defines_) {
        if (toolchain_->GetType() == ToolchainType::MSVC) {
          command += " /D" + def;
        } else {
          command += " -D" + def;
        }
      }

      for (const auto &flag : cxx_flags_) {
        command += " " + flag;
      }

      if (toolchain_->GetType() == ToolchainType::MSVC) {
        command += " /c " + abs_source.string();
      } else {
        command += " -c " + abs_source.string();
      }

      file << "  {\n";
      file << "    \"directory\": \"" << EscapeJson(cwd_str) << "\",\n";
      file << "    \"command\": \"" << EscapeJson(command) << "\",\n";
      file << "    \"file\": \"" << EscapeJson(abs_source.string()) << "\"\n";
      file << "  }";

      if (idx < sources_.size() - 1) {
        file << ",";
      }
      file << "\n";
    }

    file << "]\n";

    return *this;
  }

  /// @brief Builds the project.
  /// @return True on successful build, false on failure.
  bool Build() {
    if (sources_.empty()) {
      Error("No source files specified");
      return false;
    }

    for (const auto &source : sources_) {
      if (!platform::FileExists(source)) {
        Error("Source file not found: " + source.string());
        return false;
      }
    }

    Cache cache(SB_CACHE_DIR, release_, toolchain_.get());
    if (!cache.Init()) {
      return false;
    }

    // Compute configuration hash
    uint64_t config_hash = ComputeConfigHash();
    cache.SetConfigHash(config_hash);

    Log("Building " + name_ + " [" + toolchain_->GetName() +
        (release_ ? ", release" : ", debug") + "]...");

    int job_count = jobs_ > 0 ? jobs_ : platform::GetCpuCount();

    struct CompileJob {
      std::filesystem::path source;
      std::filesystem::path obj;
    };
    std::vector<CompileJob> jobs_to_run;
    std::vector<std::string> all_objects;

    jobs_to_run.reserve(sources_.size());
    all_objects.reserve(sources_.size());

    for (const auto &source : sources_) {
      cache.MarkUsed(source);
      auto obj_path = cache.GetObjectPath(source);
      all_objects.push_back(obj_path.string());

      if (!cache.NeedsRebuild(source, include_dirs_)) {
        Verbose("Skipping " + source.string() + " (up to date)");
        continue;
      }

      jobs_to_run.push_back({source, obj_path});
    }

    size_t compiled_count = 0;
    size_t i = 0;

    detail::ProgressBar progress(jobs_to_run.size());

    auto build_flags =
        release_ ? (release_flags_.empty() ? toolchain_->GetReleaseFlags()
                                           : release_flags_)
                 : (debug_flags_.empty() ? toolchain_->GetDebugFlags()
                                         : debug_flags_);

    std::vector<std::string> all_flags = build_flags;
    all_flags.insert(all_flags.end(), cxx_flags_.begin(), cxx_flags_.end());

    while (i < jobs_to_run.size()) {
      std::vector<pid_t> pids;
      std::vector<CompileJob *> batch;
      std::vector<std::string> batch_names;

      pids.reserve(static_cast<size_t>(job_count));
      batch.reserve(static_cast<size_t>(job_count));
      batch_names.reserve(static_cast<size_t>(job_count));

      for (int j = 0; j < job_count && i < jobs_to_run.size(); ++j, ++i) {
        auto &job = jobs_to_run[i];

        std::string src_name = job.source.filename().string();
        std::string obj_name = job.obj.filename().string();
        Log("Compiling " + src_name + " " + detail::GetArrow() + " " +
            obj_name);

        bool is_shared = (output_type_ == OutputType::SharedLib);
        Cmd cmd = toolchain_->BuildCompileCommand(
            job.source.string(), job.obj.string(), standard_, all_flags,
            include_dirs_, defines_, is_shared);

        pid_t pid = cmd.RunAsync();
        if (pid == SB_INVALID_PID) {
          progress.Finish();
          Error("Failed to start compilation for: " + job.source.string());
          return false;
        }
        pids.push_back(pid);
        batch.push_back(&job);
        batch_names.push_back(job.source.string());
      }

      progress.Update(compiled_count, batch_names);

      std::vector<std::string> in_progress = batch_names;

      bool batch_ok =
          platform::WaitAllWithProgress(pids, [&](size_t idx, bool success) {
            if (success) {
              cache.Update(batch[idx]->source, include_dirs_);
              ++compiled_count;
            }

            if (idx < in_progress.size()) {
              in_progress[idx] = "";
            }

            std::vector<std::string> still_compiling;
            for (const auto &name : in_progress) {
              if (!name.empty()) {
                still_compiling.push_back(name);
              }
            }

            progress.Update(compiled_count, still_compiling);
          });

      if (!batch_ok) {
        progress.Finish();
        Error("Compilation failed");
        return false;
      }
    }

    progress.Finish();

    std::string output = output_.empty() ? name_ : output_;
    output = ApplyOutputExtension(output);

    bool output_exists = platform::FileExists(output);

    if (compiled_count > 0 || !output_exists) {
      bool link_ok = false;

      switch (output_type_) {
      case OutputType::Executable:
        link_ok = LinkExecutable(output, all_objects);
        break;
      case OutputType::StaticLib:
        link_ok = LinkStaticLib(output, all_objects);
        break;
      case OutputType::SharedLib:
        link_ok = LinkSharedLib(output, all_objects);
        break;
      }

      if (!link_ok) {
        return false;
      }
    }

    cache.CleanOrphans();
    cache.Save();
    Log("Done!");
    return true;
  }

  /// @brief Cleans the build cache and output files.
  /// @return True on successful clean, false on failure.
  bool Clean() {
    Log("Cleaning " + name_ + "...");

    std::string output = output_.empty() ? name_ : output_;
    output = ApplyOutputExtension(output);
    if (platform::FileExists(output)) {
      Verbose("Removing " + output);
      platform::RemoveFile(output);
    }

    Cache cache(SB_CACHE_DIR, release_, toolchain_.get());
    return cache.Clean();
  }

private:
  /// @brief Computes hash of build configuration.
  /// @return Configuration hash.
  uint64_t ComputeConfigHash() const {
    std::string config;

    config += toolchain_->GetName();
    config += "|" + standard_;
    config += "|";
    config += (release_ ? "release" : "debug");

    auto flags = release_
                     ? (release_flags_.empty() ? toolchain_->GetReleaseFlags()
                                               : release_flags_)
                     : (debug_flags_.empty() ? toolchain_->GetDebugFlags()
                                             : debug_flags_);

    for (const auto &f : flags)
      config += "|" + f;
    for (const auto &f : cxx_flags_)
      config += "|" + f;
    for (const auto &f : link_flags_)
      config += "|" + f;
    for (const auto &d : defines_)
      config += "|" + d;
    for (const auto &i : include_dirs_)
      config += "|" + i;

    return detail::HashString(config);
  }

  /// @brief Escapes a string for JSON output.
  /// @param str The string to escape.
  /// @return JSON-safe escaped string.
  static std::string EscapeJson(const std::string &str) {
    std::string result;
    result.reserve(str.size() + 16);
    for (char c : str) {
      switch (c) {
      case '"':
        result += "\\\"";
        break;
      case '\\':
        result += "\\\\";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        result += c;
        break;
      }
    }
    return result;
  }

  /// @brief Applies the correct extension to output filename.
  /// @param name Base output name.
  /// @return Output name with correct extension.
  std::string ApplyOutputExtension(const std::string &name) const {
    std::string result = name;

    switch (output_type_) {
    case OutputType::Executable: {
      std::string ext = toolchain_->GetExecutableExtension();
      if (!ext.empty() &&
          (result.length() < ext.length() ||
           result.substr(result.length() - ext.length()) != ext)) {
        result += ext;
      }
      break;
    }
    case OutputType::StaticLib: {
      std::string prefix = toolchain_->GetStaticLibPrefix();
      std::string ext = toolchain_->GetStaticLibExtension();
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
      std::string prefix = toolchain_->GetSharedLibPrefix();
      std::string ext = toolchain_->GetSharedLibExtension();
      if (!prefix.empty() && result.substr(0, prefix.length()) != prefix) {
        result = prefix + result;
      }
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
  /// @return True on success.
  bool LinkExecutable(const std::string &output,
                      const std::vector<std::string> &objects) {
    Log("Linking sources " + std::string(detail::GetArrow()) + " " + output);

    Cmd cmd = toolchain_->BuildLinkCommand(output, objects, lib_dirs_, libs_,
                                           link_flags_);

    if (!cmd.Run()) {
      Error("Failed to link " + output);
      return false;
    }

    return true;
  }

  /// @brief Creates a static library.
  /// @param output Output path.
  /// @param objects Object files.
  /// @return True on success.
  bool LinkStaticLib(const std::string &output,
                     const std::vector<std::string> &objects) {
    Log("Linking static library " + std::string(detail::GetArrow()) + " " +
        output);

    platform::RemoveFile(output);

    Cmd cmd = toolchain_->BuildStaticLibCommand(output, objects);

    if (!cmd.Run()) {
      Error("Failed to create static library " + output);
      return false;
    }

    return true;
  }

  /// @brief Creates a shared library.
  /// @param output Output path.
  /// @param objects Object files.
  /// @return True on success.
  bool LinkSharedLib(const std::string &output,
                     const std::vector<std::string> &objects) {
    Log("Linking shared library " + std::string(detail::GetArrow()) + " " +
        output);

    Cmd cmd = toolchain_->BuildSharedLibCommand(output, objects, lib_dirs_,
                                                libs_, link_flags_);

    if (!cmd.Run()) {
      Error("Failed to create shared library " + output);
      return false;
    }

    return true;
  }

  std::string name_;
  std::shared_ptr<Toolchain> toolchain_;
  std::vector<std::filesystem::path> sources_;
  std::vector<std::string> include_dirs_;
  std::vector<std::string> lib_dirs_;
  std::vector<std::string> defines_;
  std::vector<std::string> libs_;
  std::vector<std::string> cxx_flags_;
  std::vector<std::string> link_flags_;
  std::vector<std::string> debug_flags_;
  std::vector<std::string> release_flags_;
  std::string output_;
  std::string standard_ = "c++17";
  int jobs_ = 0;
  bool release_ = false;
  OutputType output_type_ = OutputType::Executable;
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