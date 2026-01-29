#pragma once

#include <SDL2/SDL.h>
#include <cstdint>

namespace app {

/// @brief 2D Vector struct
struct Vec2 {
  float x = 0.0f;
  float y = 0.0f;

  Vec2 operator+(const Vec2 &other) const { return {x + other.x, y + other.y}; }
  Vec2 operator-(const Vec2 &other) const { return {x - other.x, y - other.y}; }
  Vec2 operator*(float s) const { return {x * s, y * s}; }
};

/// @brief RGBA Color struct
struct Color {
  uint8_t r = 255;
  uint8_t g = 255;
  uint8_t b = 255;
  uint8_t a = 255;

  static Color Red() { return {255, 0, 0, 255}; }
  static Color Green() { return {0, 255, 0, 255}; }
  static Color Blue() { return {0, 0, 255, 255}; }
  static Color White() { return {255, 255, 255, 255}; }
  static Color Black() { return {0, 0, 0, 255}; }
  static Color Yellow() { return {255, 255, 0, 255}; }
  static Color Cyan() { return {0, 255, 255, 255}; }
  static Color Magenta() { return {255, 0, 255, 255}; }

  static Color FromHSV(float h, float s, float v);
};

/// @brief Simple 2D renderer wrapper
class Renderer {
public:
  explicit Renderer(SDL_Renderer *sdl_renderer);

  void Clear(const Color &color = Color::Black());
  void Present();

  void DrawRect(float x, float y, float w, float h, const Color &color,
                bool filled = true);
  void DrawCircle(float cx, float cy, float radius, const Color &color,
                  bool filled = true);
  void DrawLine(float x1, float y1, float x2, float y2, const Color &color);

private:
  SDL_Renderer *renderer_;
};

} // namespace app
