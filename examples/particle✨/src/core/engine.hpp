#pragma once

#include <SDL2/SDL.h>
#include <memory>
#include <string>

namespace app {

/// @brief RAII wrapper for SDL initialization
class Engine {
public:
  Engine();
  ~Engine();

  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;

  bool IsRunning() const { return running_; }
  void Quit() { running_ = false; }

  SDL_Window *GetWindow() const { return window_; }
  SDL_Renderer *GetRenderer() const { return renderer_; }

  int GetWidth() const { return width_; }
  int GetHeight() const { return height_; }

  void SetTitle(const std::string &title);

private:
  SDL_Window *window_ = nullptr;
  SDL_Renderer *renderer_ = nullptr;
  bool running_ = true;
  int width_ = 800;
  int height_ = 600;
};

} // namespace app
