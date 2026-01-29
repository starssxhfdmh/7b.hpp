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

```cpp
sb::Project("app")
    .Sources({"main.cpp", "utils.cpp"})
    .IncludeDir("include")          // -I include
    .LinkLib("pthread")             // -lpthread
    .Pkg("sdl2")                    // pkg-config --cflags --libs sdl2
    .GenerateCompileCommands()      // For IDE support
    .Build();
```
