#pragma once

#include <platform/ui_backend.hpp>

#include <chrono>
#include <functional>
#include <mutex>
#include <unordered_map>

namespace sogen
{
    class window_compositor
    {
      public:
        using clock = std::chrono::steady_clock;

        explicit window_compositor(ui_backend& ui, std::function<clock::time_point()> now = clock::now);

        void present_surface(hwnd window, const ui_surface_desc& surface);
        void set_caret(hwnd window, const std::optional<RECT>& rect);
        void pump();
        void destroy_window(hwnd window);
        void reset();

      private:
        struct window_surface
        {
            ui_surface_desc desc{};
            std::vector<uint8_t> pixels{};
            std::vector<uint8_t> composed_pixels{};
            std::optional<RECT> caret{};
            clock::time_point caret_started{};
            bool caret_visible{};
        };

        void present(hwnd window, window_surface& surface);

        ui_backend* ui_;
        std::function<clock::time_point()> now_;
        std::mutex mutex_{};
        std::unordered_map<hwnd, window_surface> surfaces_{};
    };
}
