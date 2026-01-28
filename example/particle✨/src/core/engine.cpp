#include "engine.hpp"
#include <iostream>
#include <stdexcept>

namespace app {

Engine::Engine() {
  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
    throw std::runtime_error(std::string("SDL_Init failed: ") + SDL_GetError());
  }

  window_ = SDL_CreateWindow("7b SDL2 Demo", SDL_WINDOWPOS_CENTERED,
                             SDL_WINDOWPOS_CENTERED, width_, height_,
                             SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE);
  if (!window_) {
    SDL_Quit();
    throw std::runtime_error(std::string("SDL_CreateWindow failed: ") +
                             SDL_GetError());
  }

  renderer_ = SDL_CreateRenderer(
      window_, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
  if (!renderer_) {
    SDL_DestroyWindow(window_);
    SDL_Quit();
    throw std::runtime_error(std::string("SDL_CreateRenderer failed: ") +
                             SDL_GetError());
  }

  std::cout << "[Engine] Initialized successfully\n";
}

Engine::~Engine() {
  if (renderer_) {
    SDL_DestroyRenderer(renderer_);
  }
  if (window_) {
    SDL_DestroyWindow(window_);
  }
  SDL_Quit();
  std::cout << "[Engine] Shutdown complete\n";
}

void Engine::SetTitle(const std::string &title) {
  if (window_) {
    SDL_SetWindowTitle(window_, title.c_str());
  }
}

} // namespace app
