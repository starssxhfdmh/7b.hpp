/// @file build.cpp
/// @brief Build script for SDL2 Particle Demo using 7b build system

#include "../../7b.hpp"
using namespace sb;

BUILD {
  // Create project configuration
  auto project = Project("particle_demo")
                     .SourceDir("src", "*.cpp", true)
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
