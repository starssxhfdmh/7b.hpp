/// @file build.cpp
/// @brief Build script for SDL2 Particle Demo using 7b build system

#include "../../7b.hpp"

int main(int argc, char *argv[]) {
  SB_INIT(argc, argv);

  // Check for clean command
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "clean") {
      sb::Project("particle_demo").Clean();
      return 0;
    }
    if (std::string(argv[i]) == "release") {
      sb::Project("particle_demo")
          .Sources({"src/main.cpp", "src/core/engine.cpp",
                    "src/graphics/renderer.cpp", "src/input/input.cpp"})
          .IncludeDirs({"src"})
          .Pkg("sdl2")
          .Standard("c++17")
          .Release()
          .Build();
      return 0;
    }
  }

  // Default debug build
  sb::Project("particle_demo")
      .Sources({"src/main.cpp", "src/core/engine.cpp",
                "src/graphics/renderer.cpp", "src/input/input.cpp"})
      .IncludeDirs({"src"})
      .Pkg("sdl2")
      .Standard("c++17")
      .Build();

  return 0;
}
