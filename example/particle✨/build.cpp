/// @file build.cpp
/// @brief Build script for SDL2 Particle Demo using 7b build system

#include "../../7b.hpp"
using namespace sb;

BUILD {
  // Create project configuration
  auto project =
      Project("particle_demo")
          .Sources({"src/main.cpp", "src/core/engine.cpp",
                    "src/graphics/renderer.cpp", "src/input/input.cpp"})
          .IncludeDir("src")
          .Pkg("sdl2")
          .Standard("c++17");

  // Handle commands and flags
  if (Flag("clean")) {
    project.Clean();
    return;
  }

  if (Flag("release")) {
    project.Profile(Profile::Release());
  }

  if (Flag("commands") || Flag("compdb")) {
    project.GenerateCompileCommands();
    return;
  }

  // Build
  project.Build();

  return;
}
