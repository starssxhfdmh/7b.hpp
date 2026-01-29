/// @file build.cpp
/// @brief Build script for SDL2 Particle Demo using 7b build system

#include "../../7b.hpp"

int main(int argc, char *argv[]) {
  SB_INIT(argc, argv);

  // Create project configuration
  auto project =
      sb::Project("particle_demo")
          .Sources({"src/main.cpp", "src/core/engine.cpp",
                    "src/graphics/renderer.cpp", "src/input/input.cpp"})
          .IncludeDir("src")
          .Pkg("sdl2")
          .Standard("c++17");

  // Handle commands and flags
  if (sb::Flag("clean")) {
    project.Clean();
    return 0;
  }

  if (sb::Flag("release")) {
    project.Release();
  }

  if (sb::Flag("commands") || sb::Flag("compdb")) {
    project.GenerateCompileCommands();
    return 0;
  }

  // Generate compile_commands.json automatically before building
  project.GenerateCompileCommands();

  // Build
  project.Build();

  return 0;
}
