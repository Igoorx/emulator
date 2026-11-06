#include "emulation_test_utils.hpp"
#include <window_compositor.hpp>

namespace sogen::test
{
    namespace
    {
        class surface_recording_backend : public ui_backend
        {
          public:
            void set_event_sink(event_sink) override
            {
            }

            void pump_events() override
            {
            }

            void present_surface(const hwnd target, const ui_surface_desc& surface) override
            {
                this->window = target;
                this->desc = surface;
                this->desc.pixels = nullptr;
                const auto* bytes = static_cast<const uint8_t*>(surface.pixels);
                this->pixels.assign(bytes, bytes + static_cast<size_t>(surface.stride) * surface.height);
                ++this->presentations;
            }

            hwnd window{};
            ui_surface_desc desc{};
            std::vector<uint8_t> pixels{};
            size_t presentations{};
        };

        class WindowCompositorTest : public testing::Test
        {
          protected:
            surface_recording_backend ui{};
            window_compositor::clock::time_point now{};
            window_compositor graphics{ui, [this] { return this->now; }};
        };
    }

    TEST_F(WindowCompositorTest, XorClipsToPixelsAndPreservesAlphaPaddingAndSource)
    {
        for (const auto format : {ui_surface_format::bgra8, ui_surface_format::rgba8})
        {
            const std::vector<uint8_t> source{0x12, 0x34, 0x56, 0x78, 0xff, 0x80, 0x00, 0x42, 0xaa, 0xbb, 0xcc, 0xdd};
            graphics.present_surface(1, {.width = 2, .height = 1, .stride = 12, .format = format, .pixels = source.data()});
            graphics.set_caret(1, RECT{-10, -20, 1, 30});
            EXPECT_EQ((std::vector<uint8_t>{0xed, 0xcb, 0xa9, 0x78, 0xff, 0x80, 0x00, 0x42, 0xaa, 0xbb, 0xcc, 0xdd}), ui.pixels);
            EXPECT_EQ(format, ui.desc.format);
            graphics.set_caret(1, std::nullopt);
            EXPECT_EQ(source, ui.pixels);
            EXPECT_EQ(0x12, source.front());
        }
    }

    TEST_F(WindowCompositorTest, RepaintingAndMovingRestoreTheLatestUnderlyingPixels)
    {
        std::array<uint32_t, 2> source{0xff123456, 0xffabcdef};
        const ui_surface_desc desc{.width = 2, .height = 1, .stride = 8, .pixels = source.data()};
        graphics.present_surface(1, desc);
        graphics.set_caret(1, RECT{0, 0, 1, 1});
        source = {0xff010203, 0xff102030};
        graphics.present_surface(1, desc);
        EXPECT_EQ((std::vector<uint8_t>{0xfc, 0xfd, 0xfe, 0xff, 0x30, 0x20, 0x10, 0xff}), ui.pixels);
        graphics.set_caret(1, RECT{1, 0, 2, 1});
        EXPECT_EQ((std::vector<uint8_t>{0x03, 0x02, 0x01, 0xff, 0xcf, 0xdf, 0xef, 0xff}), ui.pixels);
        graphics.set_caret(1, std::nullopt);
        EXPECT_EQ((std::vector<uint8_t>{0x03, 0x02, 0x01, 0xff, 0x30, 0x20, 0x10, 0xff}), ui.pixels);
        EXPECT_EQ((std::array<uint32_t, 2>{0xff010203, 0xff102030}), source);
    }

    TEST_F(WindowCompositorTest, BlinkingRestoresAndInvertsWithoutAccumulatingChanges)
    {
        const uint32_t pixel = 0xff123456;
        graphics.set_caret(1, RECT{0, 0, 1, 1});
        graphics.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        const auto visible = ui.pixels;
        now += std::chrono::milliseconds(529);
        graphics.pump();
        EXPECT_EQ(1u, ui.presentations);
        now += std::chrono::milliseconds(1);
        graphics.pump();
        EXPECT_EQ((std::vector<uint8_t>{0x56, 0x34, 0x12, 0xff}), ui.pixels);
        now += std::chrono::milliseconds(530);
        graphics.pump();
        EXPECT_EQ(visible, ui.pixels);
        EXPECT_EQ(3u, ui.presentations);
        graphics.set_caret(1, std::nullopt);
        const auto hidden = ui.pixels;
        now += std::chrono::seconds(10);
        graphics.pump();
        EXPECT_EQ(hidden, ui.pixels);
        EXPECT_EQ(4u, ui.presentations);
    }

    TEST_F(WindowCompositorTest, DestroyAndResetDiscardSurfacesAndBlinkState)
    {
        const uint32_t pixel = 0xff123456;
        graphics.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        graphics.set_caret(1, RECT{0, 0, 1, 1});
        graphics.destroy_window(1);
        graphics.set_caret(1, RECT{0, 0, 1, 1});
        EXPECT_EQ(2u, ui.presentations);
        graphics.reset();
        now += std::chrono::milliseconds(530);
        graphics.pump();
        EXPECT_EQ(2u, ui.presentations);
        graphics.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        EXPECT_EQ((std::vector<uint8_t>{0x56, 0x34, 0x12, 0xff}), ui.pixels);
    }
}
