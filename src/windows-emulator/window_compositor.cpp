#include "std_include.hpp"
#include "window_compositor.hpp"

namespace sogen
{
    window_compositor::window_compositor(ui_backend& ui, std::function<clock::time_point()> now)
        : ui_(&ui),
          now_(std::move(now))
    {
    }

    void window_compositor::present_surface(const hwnd window, const ui_surface_desc& surface)
    {
        if (!surface.pixels || surface.width <= 0 || surface.height <= 0 || surface.stride <= 0 ||
            static_cast<size_t>(surface.stride) < static_cast<size_t>(surface.width) * 4)
        {
            return;
        }

        const std::lock_guard lock(this->mutex_);
        auto& state = this->surfaces_[window];
        state.desc = surface;
        state.desc.pixels = nullptr;
        const auto* pixels = static_cast<const uint8_t*>(surface.pixels);
        state.pixels.assign(pixels, pixels + static_cast<size_t>(surface.stride) * static_cast<size_t>(surface.height));
        this->present(window, state);
    }

    void window_compositor::set_caret(const hwnd window, const std::optional<RECT>& rect)
    {
        const std::lock_guard lock(this->mutex_);
        auto& state = this->surfaces_[window];
        state.caret = rect;
        state.caret_started = this->now_();
        state.caret_visible = rect.has_value();
        this->present(window, state);
    }

    void window_compositor::pump()
    {
        const std::lock_guard lock(this->mutex_);
        const auto now = this->now_();
        for (auto& [window, state] : this->surfaces_)
        {
            if (!state.caret)
            {
                continue;
            }
            const bool visible = ((now - state.caret_started) / std::chrono::milliseconds(530)) % 2 == 0;
            if (visible != state.caret_visible)
            {
                state.caret_visible = visible;
                this->present(window, state);
            }
        }
    }

    void window_compositor::destroy_window(const hwnd window)
    {
        const std::lock_guard lock(this->mutex_);
        this->surfaces_.erase(window);
        this->ui_->destroy_window(window);
    }

    void window_compositor::reset()
    {
        const std::lock_guard lock(this->mutex_);
        this->surfaces_.clear();
        this->ui_->reset();
    }

    void window_compositor::present(const hwnd window, window_surface& surface)
    {
        if (surface.pixels.empty())
        {
            return;
        }

        auto desc = surface.desc;
        desc.pixels = surface.pixels.data();
        if (surface.caret && surface.caret_visible)
        {
            surface.composed_pixels = surface.pixels;
            const auto& rect = *surface.caret;
            const auto left = std::clamp<int>(rect.left, 0, desc.width);
            const auto top = std::clamp<int>(rect.top, 0, desc.height);
            const auto right = std::clamp<int>(rect.right, 0, desc.width);
            const auto bottom = std::clamp<int>(rect.bottom, 0, desc.height);
            for (int y = top; y < bottom; ++y)
            {
                for (int x = left; x < right; ++x)
                {
                    const auto offset = static_cast<size_t>(y) * static_cast<size_t>(desc.stride) + static_cast<size_t>(x) * 4;
                    for (size_t channel = 0; channel < 3; ++channel)
                    {
                        surface.composed_pixels[offset + channel] ^= 0xff;
                    }
                }
            }
            desc.pixels = surface.composed_pixels.data();
        }
        this->ui_->present_surface(window, desc);
    }
}
