# 7b

**The C++ Build System for C++ Developers.**

> Stop learning new build syntaxes. Build your C++ projects using the language you already know.

## What is this?
**7b** is a header-only library that lets you write build scripts in standard **C++17**.

It replaces complex build systems like CMake or Make with a single C++ file. It handles parallel compilation, dependency tracking, and incremental builds automatically.

## Why use it?
- **It's just C++**: Use loops, strings, and standard libraries to handle complex build logic.
- **Zero Friction**: It **rebuilds itself**. Edit `build.cpp`, run `./build`, and 7b automatically recompiles the build script before running it.
- **Header-Only**: No installation required. Just drop `7b.hpp` in your repo.
- **Fast**: Automatic parallel compilation and incremental builds.

## Quick Start

**1. Create `build.cpp`**:
```cpp
#include "7b.hpp"

int main(int argc, char** argv) {
    SB_INIT(argc, argv); // Enables self-rebuilding

    sb::Project("myapp")
        .Sources({"src/main.cpp", "src/utils.cpp"})
        .Build();
    
    return 0;
}

// or use the BUILD macro
BUILD {
    sb::Project("myapp")
        .Sources({"src/main.cpp", "src/utils.cpp"})
        .Build();

    return;
}
```

**2. Bootstrap & Run**:
Compile it once using your system compiler:
```bash
# Linux/macOS
g++ build.cpp -std=c++17 -o build
./build

# Windows (MSVC use developer command prompt)
cl build.cpp /std:c++17 /EHsc
build.exe
```
From now on, just run `./build`. If you modify `build.cpp`, it reconfigures itself automatically.

## Cheatsheet

### Project Configuration

```cpp
sb::Project("app")
    .SourceDir("src", "*.cpp", true)     // All .cpp in src/ recursively
    .Sources({"main.cpp"})               // Glob patterns: *.cpp, **/*.cpp
    .IncludeDir("include")               // Add include directory (-I)
    .LibDir("libs")                      // Add library directory (-L)
    .LinkLib("pthread")                  // Link shared library (-l)
    .LinkLibStatic("utils")              // Link static library (Linux only)
    .Pkg("sdl2")                         // Use pkg-config (Unix only)
    .Define("NDEBUG")                    // Add preprocessor definition (-D)
    .CxxFlag("-Wall")                    // Add custom compiler flag
    .LinkFlag("-s")                      // Add custom linker flag
    .Standard("c++20")                   // Set C++ standard (default: c++17)
    .Output("bin/myapp")                 // Set output binary name
    .Type(sb::OutputType::SharedLib)     // Executable, StaticLib, or SharedLib
    .Jobs(4)                             // Set concurrent compile jobs (default: auto)
    .Profile(sb::Profile::Release())     // Set build profile (default: Debug)
    .GenerateCompileCommands()           // Generate compile_commands.json for IDEs
    .Build();                            // Run the build
```

### CLI Arguments
```cpp
// Check if flag exists: ./build --clean
if (sb::Flag("clean")) {
    sb::Project("app").Clean();
    return 0;
}

// Get option value: ./build --target=release
std::string mode = sb::Option("target", "debug");
if (mode == "release") {
    // ...
}
```

### Custom Commands
```cpp
// Run arbitrary shell commands
sb::Cmd()
    .Arg("tar")
    .Args({"-cvf", "assets.tar", "assets/"})
    .Run(); // Returns true on success
```

### Configuration Macros
Define these **before** `#include "7b.hpp"`.

| Macro | Description |
|-------|-------------|
| `SB_QUIET` | Minimal output (errors only) |
| `SB_VERBOSE` | Enable verbose debug logging |
| `SB_NO_COLORS` | Disable colored output |
| `SB_CACHE_DIR` | Set custom cache directory (default `.7b`) |
| `SB_TOOLCHAIN` | Force toolchain: `gcc`, `clang`, or `msvc` |
