#include "input.hpp"

namespace app {

void Input::Update() {
  keys_pressed_.clear();
  keys_released_.clear();
  mouse_pressed_.clear();

  SDL_Event event;
  while (SDL_PollEvent(&event)) {
    switch (event.type) {
    case SDL_QUIT:
      quit_requested_ = true;
      break;

    case SDL_KEYDOWN:
      if (!event.key.repeat) {
        keys_down_.insert(event.key.keysym.scancode);
        keys_pressed_.insert(event.key.keysym.scancode);
      }
      break;

    case SDL_KEYUP:
      keys_down_.erase(event.key.keysym.scancode);
      keys_released_.insert(event.key.keysym.scancode);
      break;

    case SDL_MOUSEBUTTONDOWN:
      mouse_down_.insert(event.button.button);
      mouse_pressed_.insert(event.button.button);
      break;

    case SDL_MOUSEBUTTONUP:
      mouse_down_.erase(event.button.button);
      break;

    case SDL_MOUSEMOTION:
      mouse_x_ = event.motion.x;
      mouse_y_ = event.motion.y;
      break;
    }
  }
}

bool Input::IsKeyDown(SDL_Scancode key) const {
  return keys_down_.count(key) > 0;
}

bool Input::IsKeyPressed(SDL_Scancode key) const {
  return keys_pressed_.count(key) > 0;
}

bool Input::IsKeyReleased(SDL_Scancode key) const {
  return keys_released_.count(key) > 0;
}

bool Input::IsMouseButtonDown(int button) const {
  return mouse_down_.count(button) > 0;
}

bool Input::IsMouseButtonPressed(int button) const {
  return mouse_pressed_.count(button) > 0;
}

} // namespace app
