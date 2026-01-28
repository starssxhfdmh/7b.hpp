/// @file 7b.hpp
/// @brief A single-header C++ build system.
/// @author starssxhfdmh
/// @copyright Copyright (c) 2026 starssxhfdmh. MIT License.
/// @version 1.0.1
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
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
/// @brief Windows compatibility typedef for process ID.
typedef int pid_t;
#else
#include <sys/wait.h>
#include <unistd.h>
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

} // namespace detail

/// @brief Logs an error message to stderr.
/// @param msg The error message to display.
/// @note Error messages are always shown regardless of SB_QUIET setting.
inline void Error(std::string_view msg) {
  std::cerr << detail::kColorRed << "[7b] ERROR: " << detail::kColorReset << msg
            << "\n";
}

/// @brief Logs a warning message to stdout.
/// @param msg The warning message to display.
/// @note Hidden when SB_QUIET is defined.
inline void Warn([[maybe_unused]] std::string_view msg) {
#ifndef SB_QUIET
  std::cout << detail::kColorYellow << "[7b] WARN: " << detail::kColorReset
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
/// @return The hash value, or std::nullopt if the file cannot be read.
inline std::optional<uint64_t> HashFile(const std::filesystem::path &path) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return std::nullopt;
  }

  std::ostringstream ss;
  ss << file.rdbuf();
  std::string content = ss.str();
  return Fnv1aHash(reinterpret_cast<const uint8_t *>(content.data()),
                   content.size());
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
  auto sctp = std::chrono::time_point_cast<std::chrono::nanoseconds>(
      ftime - std::filesystem::file_time_type::clock::now() +
      std::chrono::system_clock::now());
  return sctp.time_since_epoch().count();
}

/// @brief Checks if a file exists at the given path.
/// @param path Path to check.
/// @return True if the file exists, false otherwise.
inline bool FileExists(const std::filesystem::path &path) {
  return std::filesystem::exists(path);
}

/// @brief Creates a directory and all parent directories.
/// @param path Directory path to create.
/// @return True on success, false on failure.
inline bool CreateDirs(const std::filesystem::path &path) {
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  return !ec;
}

/// @brief Runs a command synchronously and waits for completion.
/// @param args Command and arguments as a vector of strings.
/// @return Exit code of the command, or -1 on error.
/// @details On Windows, uses system(). On Unix, uses fork/exec.
inline int RunCommand(const std::vector<std::string> &args) {
  if (args.empty()) {
    return -1;
  }

#ifdef _WIN32
  std::string cmd;
  for (size_t i = 0; i < args.size(); ++i) {
    if (i > 0)
      cmd += " ";
    if (args[i].find(' ') != std::string::npos) {
      cmd += "\"" + args[i] + "\"";
    } else {
      cmd += args[i];
    }
  }
  return std::system(cmd.c_str());
#else
  pid_t pid = fork();
  if (pid == -1) {
    return -1;
  }

  if (pid == 0) {
    std::vector<char *> argv;
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
/// @return Process ID of the spawned process, or -1 on error.
/// @note On Windows, this falls back to synchronous execution and returns -1.
inline pid_t RunCommandAsync(const std::vector<std::string> &args) {
#ifdef _WIN32
  // Windows fallback: run synchronously
  // Returns -1 to indicate no async process was created
  RunCommand(args);
  return -1;
#else
  pid_t pid = fork();
  if (pid == 0) {
    std::vector<char *> argv;
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

/// @brief Waits for multiple processes to complete.
/// @param pids Vector of process IDs to wait for.
/// @return True if all processes exited successfully (code 0), false otherwise.
/// @note On Windows, always returns true since RunCommandAsync runs
/// synchronously.
inline bool WaitAll(const std::vector<pid_t> &pids) {
#ifdef _WIN32
  (void)pids; // Suppress unused parameter warning
  return true;
#else
  bool all_ok = true;
  for (pid_t pid : pids) {
    if (pid <= 0) {
      continue; // Skip invalid pids
    }
    int status;
    if (waitpid(pid, &status, 0) == -1) {
      all_ok = false;
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      all_ok = false;
    }
  }
  return all_ok;
#endif
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
  char buf[MAX_PATH];
  DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
  if (len > 0 && len < MAX_PATH) {
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
/// @note On Windows, this uses system() and exit() instead of exec().
inline void Exec(const std::vector<std::string> &args) {
  if (args.empty())
    return;

#ifdef _WIN32
  std::string cmd;
  for (size_t i = 0; i < args.size(); ++i) {
    if (i > 0)
      cmd += " ";
    if (args[i].find(' ') != std::string::npos) {
      cmd += "\"" + args[i] + "\"";
    } else {
      cmd += args[i];
    }
  }
  int result = std::system(cmd.c_str());
  std::exit(result);
#else
  std::vector<char *> argv;
  for (const auto &arg : args) {
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
  /// @return True if recompilation is needed, false if up to date.
  /// @details A file needs rebuild if:
  ///          - Its content hash differs from cached hash
  ///          - Its hash is not in the cache
  ///          - The corresponding object file doesn't exist
  bool NeedsRebuild(const std::filesystem::path &source) const {
    auto hash = detail::HashFile(source);
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
    std::string path_str = source.string();
    uint64_t path_hash = detail::HashString(path_str);
    std::string name = source.stem().string() + "_" +
                       detail::HashToHex(path_hash).substr(0, 8) + ".o";
    return obj_dir_ / name;
  }

  /// @brief Updates the cached hash for a source file.
  /// @param source Path to the source file.
  /// @details Call this after successfully compiling a source file.
  void Update(const std::filesystem::path &source) {
    auto hash = detail::HashFile(source);
    if (hash) {
      hashes_[source.string()] = *hash;
    }
  }

  /// @brief Saves the cache state to disk.
  /// @note Writes to .cache file in the object directory.
  void Save() const {
    std::ofstream file(cache_file_);
    if (!file) {
      Warn("Failed to save cache");
      return;
    }

    for (const auto &[path, hash] : hashes_) {
      file << path << " " << detail::HashToHex(hash) << "\n";
    }
  }

  /// @brief Removes the entire cache directory.
  /// @return True on success, false on failure.
  bool Clean() {
    std::error_code ec;
    std::filesystem::remove_all(cache_dir_, ec);
    hashes_.clear();
    return !ec;
  }

private:
  /// @brief Loads cache state from disk.
  void Load() {
    std::ifstream file(cache_file_);
    if (!file) {
      return;
    }

    std::string line;
    while (std::getline(file, line)) {
      size_t space = line.rfind(' ');
      if (space != std::string::npos && space > 0) {
        std::string path = line.substr(0, space);
        std::string hash_hex = line.substr(space + 1);

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
  }

  std::filesystem::path cache_dir_;  ///< Base cache directory (.7b)
  std::filesystem::path obj_dir_;    ///< Object file directory
  std::filesystem::path cache_file_; ///< Path to .cache file
  std::unordered_map<std::string, uint64_t>
      hashes_; ///< Source path to hash map
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
    for (auto arg : args) {
      args_.emplace_back(arg);
    }
    return *this;
  }

  /// @brief Adds multiple arguments from a vector.
  /// @param args The arguments to add.
  /// @return Reference to this Cmd for chaining.
  Cmd &Args(const std::vector<std::string> &args) {
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
      if (args_[i].find(' ') != std::string::npos) {
        result += "\"" + args_[i] + "\"";
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
  const std::vector<std::string> &GetArgs() const { return args_; }

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
    for (auto file : files) {
      sources_.emplace_back(file);
    }
    return *this;
  }

  /// @brief Adds multiple source files from a vector.
  /// @param files Source file paths to add.
  /// @return Reference to this Project for chaining.
  Project &Sources(const std::vector<std::string> &files) {
    for (const auto &file : files) {
      sources_.emplace_back(file);
    }
    return *this;
  }

  /// @brief Adds a single source file.
  /// @param file Source file path to add.
  /// @return Reference to this Project for chaining.
  Project &Source(std::string_view file) {
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
  Project &Pkg(std::string_view name) {
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

  /// @brief Overrides default debug build flags.
  /// @param flags New debug flags.
  /// @return Reference to this Project for chaining.
  Project &DebugFlags(std::initializer_list<std::string_view> flags) {
    debug_flags_.clear();
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

    for (const auto &source : sources_) {
      auto obj_path = cache.GetObjectPath(source);
      all_objects.push_back(obj_path);

      if (!cache.NeedsRebuild(source)) {
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

        pids.push_back(cmd.RunAsync());
        batch.push_back(&job);
      }

      if (!platform::WaitAll(pids)) {
        Error("Compilation failed");
        return false;
      }

      for (auto *job : batch) {
        cache.Update(job->source);
        ++compiled_count;
      }
    }

    std::string output = output_.empty() ? name_ : output_;
    bool output_exists = platform::FileExists(output);

    if (compiled_count > 0 || !output_exists) {
      Verbose("Linking " + output);

      Cmd cmd;
      cmd.Arg(SB_CXX);

      for (const auto &obj : all_objects) {
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
        Error("Failed to link " + output);
        return false;
      }
    }

    cache.Save();
    Log("Built: " + output + " (" + std::to_string(compiled_count) + "/" +
        std::to_string(sources_.size()) + " compiled)");
    Log("Done!");
    return true;
  }

  /// @brief Cleans the build cache for this project.
  /// @return True on successful clean, false on failure.
  bool Clean() {
    Log("Cleaning " + name_ + "...");
    Cache cache(SB_CACHE_DIR, release_);
    return cache.Clean();
  }

private:
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