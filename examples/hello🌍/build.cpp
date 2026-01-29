/// @file build.cpp
/// @brief Build script for Hello World example

#include "../../7b.hpp"
using namespace sb;

BUILD {
  Project("hello")
    .SourceDir("src")
    .IncludeDir("src")
    .Standard("c++17")
    .Build();
}
