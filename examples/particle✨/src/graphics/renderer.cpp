#include "renderer.hpp"
#include <cmath>

namespace app {

Color Color::FromHSV(float h, float s, float v) {
  float c = v * s;
  float x = c * (1.0f - std::abs(std::fmod(h / 60.0f, 2.0f) - 1.0f));
  float m = v - c;

  float r = 0, g = 0, b = 0;
  if (h < 60) {
    r = c;
    g = x;
  } else if (h < 120) {
    r = x;
    g = c;
  } else if (h < 180) {
    g = c;
    b = x;
  } else if (h < 240) {
    g = x;
    b = c;
  } else if (h < 300) {
    r = x;
    b = c;
  } else {
    r = c;
    b = x;
  }

  return {static_cast<uint8_t>((r + m) * 255),
          static_cast<uint8_t>((g + m) * 255),
          static_cast<uint8_t>((b + m) * 255), 255};
}

Renderer::Renderer(SDL_Renderer *sdl_renderer) : renderer_(sdl_renderer) {}

void Renderer::Clear(const Color &color) {
  SDL_SetRenderDrawColor(renderer_, color.r, color.g, color.b, color.a);
  SDL_RenderClear(renderer_);
}

void Renderer::Present() { SDL_RenderPresent(renderer_); }

void Renderer::DrawRect(float x, float y, float w, float h, const Color &color,
                        bool filled) {
  SDL_SetRenderDrawColor(renderer_, color.r, color.g, color.b, color.a);
  SDL_FRect rect = {x, y, w, h};
  if (filled) {
    SDL_RenderFillRectF(renderer_, &rect);
  } else {
    SDL_RenderDrawRectF(renderer_, &rect);
  }
}

void Renderer::DrawCircle(float cx, float cy, float radius, const Color &color,
                          bool filled) {
  SDL_SetRenderDrawColor(renderer_, color.r, color.g, color.b, color.a);

  if (filled) {
    for (int y = static_cast<int>(-radius); y <= static_cast<int>(radius);
         ++y) {
      int dx = static_cast<int>(std::sqrt(radius * radius - y * y));
      SDL_RenderDrawLineF(renderer_, cx - dx, cy + y, cx + dx, cy + y);
    }
  } else {
    constexpr int segments = 64;
    float prev_x = cx + radius;
    float prev_y = cy;
    for (int i = 1; i <= segments; ++i) {
      float angle = (2.0f * 3.14159265f * i) / segments;
      float new_x = cx + radius * std::cos(angle);
      float new_y = cy + radius * std::sin(angle);
      SDL_RenderDrawLineF(renderer_, prev_x, prev_y, new_x, new_y);
      prev_x = new_x;
      prev_y = new_y;
    }
  }
}

void Renderer::DrawLine(float x1, float y1, float x2, float y2,
                        const Color &color) {
  SDL_SetRenderDrawColor(renderer_, color.r, color.g, color.b, color.a);
  SDL_RenderDrawLineF(renderer_, x1, y1, x2, y2);
}

} // namespace app
