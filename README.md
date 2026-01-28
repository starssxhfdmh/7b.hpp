# 7b

A minimal, header-only C++ build system. Write your build logic in pure C++.

## Features

- **Header-only** — just include and use
- **Self-rebuilding** — automatically recompiles when build script changes
- **Parallel compilation** — utilizes all CPU cores
- **Incremental builds** — only recompiles changed files
- **pkg-config support** — easy dependency management
- **Cross-platform** — Linux and Windows

## Quick Start

**1. Create `build.cpp`:**

```cpp
#include "7b.hpp"

int main(int argc, char** argv) {
    SB_INIT(argc, argv);
    
    sb::Project("myapp")
        .Sources({"src/main.cpp", "src/utils.cpp"})
        .Build();
    
    return 0;
}
```

**2. Bootstrap:**

```bash
g++ -std=c++17 build.cpp -o build
./build
```

After the initial bootstrap, just run `./build` — it rebuilds itself when `build.cpp` changes.

## API

```cpp
sb::Project("name")
    // Sources
    .Source("file.cpp")
    .Sources({"a.cpp", "b.cpp"})
    
    // Include paths (-I)
    .IncludeDir("include")
    .IncludeDirs({"inc1", "inc2"})
    
    // Libraries (-l)
    .LinkLib("pthread")
    .LinkLibs({"ssl", "crypto"})
    .LinkLibStatic("mylib")
    
    // Library paths (-L)
    .LibDir("lib")
    .LibDirs({"lib1", "lib2"})
    
    // Preprocessor (-D)
    .Define("DEBUG")
    .Defines({"VERSION=1", "FEATURE_X"})
    
    // Flags
    .CxxFlag("-fPIC")
    .CxxFlags({"-march=native", "-flto"})
    .LinkFlag("-static")
    .LinkFlags({"-s", "-flto"})
    
    // pkg-config
    .Pkg("libcurl")
    
    // Options
    .Standard("c++20")          // default: c++17
    .Output("bin/myapp")        // default: project name
    .Jobs(4)                    // default: auto-detect
    .Release()                  // or .Debug() (default)
    
    // Output type
    .Type(sb::OutputType::Executable)   // default
    .Type(sb::OutputType::StaticLib)    // creates libname.a / name.lib
    .Type(sb::OutputType::SharedLib)    // creates libname.so / name.dll / libname.dylib
    
    // Override default build flags
    .DebugFlags({"-g3", "-Og", "-Wall", "-Wextra", "-Wpedantic"})
    .ReleaseFlags({"-O3", "-DNDEBUG", "-march=native", "-flto"})
    
    // Generate compile_commands.json (for clangd/IDE support)
    .GenerateCompileCommands()                      // default: ./compile_commands.json
    .GenerateCompileCommands("build/compile_commands.json")
    
    // Build
    .Build();                   // returns bool
    
    // Clean
    .Clean();
```

## Configuration

Define before including `7b.hpp`:

| Macro | Description | Default |
|-------|-------------|---------|
| `SB_CXX` | Compiler | `g++` |
| `SB_CACHE_DIR` | Cache directory | `.7b` |
| `SB_QUIET` | Errors only | — |
| `SB_VERBOSE` | Detailed output | — |
| `SB_NO_COLORS` | Disable colors | — |
| `SB_DEBUG_FLAGS` | Debug flags | `-g -O0 -Wall -Wextra` |
| `SB_RELEASE_FLAGS` | Release flags | `-O2 -DNDEBUG -Wall` |

```cpp
#define SB_CXX "clang++"
#define SB_QUIET
#include "7b.hpp"
```

## Example: Multi-target Build

```cpp
#include "7b.hpp"

int main(int argc, char** argv) {
    SB_INIT(argc, argv);
    
    bool release = argc > 1 && std::string(argv[1]) == "release";
    
    auto project = sb::Project("myapp")
        .Sources({"src/main.cpp", "src/engine.cpp"})
        .IncludeDir("include")
        .Pkg("sdl2")
        .LinkLib("m");
    
    if (release) {
        project.Release();
    }
    
    return project.Build() ? 0 : 1;
}
```

```bash
./build          # debug build
./build release  # release build
```

## Requirements

- C++17 compiler (GCC 8+, Clang 7+, MSVC 2019+)
- POSIX or Windows

## License

MIT
