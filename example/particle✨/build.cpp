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

  // Check for commands
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg == "clean") {
      project.Clean();
      return 0;
    }

    if (arg == "release") {
      project.Release();
    }

    if (arg == "commands" || arg == "compdb") {
      project.GenerateCompileCommands();
      return 0;
    }
  }

  // Generate compile_commands.json automatically before building
  project.GenerateCompileCommands();

  // Build
  project.Build();

  return 0;
}
