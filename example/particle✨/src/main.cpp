#include "core/engine.hpp"
#include "graphics/renderer.hpp"
#include "input/input.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <vector>

/// @brief Particle struct for the demo
struct Particle {
  app::Vec2 pos;
  app::Vec2 vel;
  float hue;
  float radius;
  float life;
  float max_life;
};

/// @brief Main demo application
class ParticleDemo {
public:
  ParticleDemo() : engine_(), renderer_(engine_.GetRenderer()) {
    std::cout << "[Demo] Particle demo initialized\n";
    std::cout << "[Demo] Click to spawn particles, ESC to quit\n";
  }

  void Run() {
    while (engine_.IsRunning()) {
      float dt = 1.0f / 60.0f;

      input_.Update();

      if (input_.ShouldQuit() || input_.IsKeyPressed(SDL_SCANCODE_ESCAPE)) {
        engine_.Quit();
        continue;
      }

      // Spawn particles on mouse click
      if (input_.IsMouseButtonDown(SDL_BUTTON_LEFT)) {
        SpawnParticles(static_cast<float>(input_.GetMouseX()),
                       static_cast<float>(input_.GetMouseY()), 5);
      }

      // Update particles
      UpdateParticles(dt);

      // Draw
      renderer_.Clear(app::Color{20, 20, 30, 255});

      // Draw instructions
      DrawTitle();

      // Draw particles
      for (const auto &p : particles_) {
        float alpha = p.life / p.max_life;
        auto color = app::Color::FromHSV(p.hue, 1.0f, 1.0f);
        color.a = static_cast<uint8_t>(alpha * 255);
        renderer_.DrawCircle(p.pos.x, p.pos.y, p.radius * alpha, color, true);
      }

      // Draw FPS
      frame_count_++;

      renderer_.Present();
    }
  }

private:
  void SpawnParticles(float x, float y, int count) {
    for (int i = 0; i < count; ++i) {
      float angle = static_cast<float>(rand()) / RAND_MAX * 6.28318f;
      float speed = 50.0f + static_cast<float>(rand()) / RAND_MAX * 150.0f;

      Particle p;
      p.pos = {x, y};
      p.vel = {std::cos(angle) * speed, std::sin(angle) * speed};
      p.hue = hue_offset_ + static_cast<float>(rand()) / RAND_MAX * 60.0f;
      p.radius = 5.0f + static_cast<float>(rand()) / RAND_MAX * 15.0f;
      p.life = 1.0f + static_cast<float>(rand()) / RAND_MAX * 1.5f;
      p.max_life = p.life;

      particles_.push_back(p);
    }

    hue_offset_ = std::fmod(hue_offset_ + 2.0f, 360.0f);
  }

  void UpdateParticles(float dt) {
    for (auto &p : particles_) {
      p.pos = p.pos + p.vel * dt;
      p.vel.y += 150.0f * dt; // Gravity
      p.life -= dt;
    }

    // Remove dead particles
    particles_.erase(
        std::remove_if(particles_.begin(), particles_.end(),
                       [](const Particle &p) { return p.life <= 0; }),
        particles_.end());
  }

  void DrawTitle() {
    // Draw a simple border
    renderer_.DrawRect(0, 0, static_cast<float>(engine_.GetWidth()), 4.0f,
                       app::Color::Cyan(), true);
    renderer_.DrawRect(0, static_cast<float>(engine_.GetHeight()) - 4,
                       static_cast<float>(engine_.GetWidth()), 4.0f,
                       app::Color::Cyan(), true);
  }

  app::Engine engine_;
  app::Renderer renderer_;
  app::Input input_;
  std::vector<Particle> particles_;
  float hue_offset_ = 0.0f;
  int frame_count_ = 0;
};

int main([[maybe_unused]] int argc, [[maybe_unused]] char *argv[]) {
  try {
    ParticleDemo demo;
    demo.Run();
  } catch (const std::exception &e) {
    std::cerr << "[FATAL] " << e.what() << std::endl;
    return 1;
  }

  return 0;
}
