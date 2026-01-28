#pragma once

#include <SDL2/SDL.h>
#include <unordered_set>

namespace app {

/// @brief Keyboard and mouse input handler
class Input {
public:
  void Update();

  bool IsKeyDown(SDL_Scancode key) const;
  bool IsKeyPressed(SDL_Scancode key) const;
  bool IsKeyReleased(SDL_Scancode key) const;

  bool IsMouseButtonDown(int button) const;
  bool IsMouseButtonPressed(int button) const;

  int GetMouseX() const { return mouse_x_; }
  int GetMouseY() const { return mouse_y_; }

  bool ShouldQuit() const { return quit_requested_; }

private:
  std::unordered_set<SDL_Scancode> keys_down_;
  std::unordered_set<SDL_Scancode> keys_pressed_;
  std::unordered_set<SDL_Scancode> keys_released_;
  std::unordered_set<int> mouse_down_;
  std::unordered_set<int> mouse_pressed_;

  int mouse_x_ = 0;
  int mouse_y_ = 0;
  bool quit_requested_ = false;
};

} // namespace app
