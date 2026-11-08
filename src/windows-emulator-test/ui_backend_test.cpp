#include "emulation_test_utils.hpp"
#include <platform/ui_backend.hpp>

namespace sogen::test
{
    namespace
    {
        class surface_recording_backend : public ui_backend
        {
          public:
            using ui_backend::ui_backend;

            void set_event_sink(event_sink) override
            {
            }

            void pump_events() override
            {
                if (this->on_pump)
                {
                    this->on_pump();
                }
            }

            void render_surface(const hwnd target, const ui_surface_desc& surface) override
            {
                this->window = target;
                this->desc = surface;
                this->desc.pixels = nullptr;
                const auto* bytes = static_cast<const uint8_t*>(surface.pixels);
                this->pixels.assign(bytes, bytes + static_cast<size_t>(surface.stride) * surface.height);
                ++this->presentations;
            }

            std::function<void()> on_pump{};
            hwnd window{};
            ui_surface_desc desc{};
            std::vector<uint8_t> pixels{};
            size_t presentations{};
        };

        class UiBackendTest : public testing::Test
        {
          protected:
            ui_backend::clock::time_point now{};
            surface_recording_backend ui{[this] { return this->now; }};
        };
    }

    TEST_F(UiBackendTest, XorClipsToPixelsAndPreservesAlphaPaddingAndSource)
    {
        for (const auto format : {ui_surface_format::bgra8, ui_surface_format::rgba8})
        {
            const std::vector<uint8_t> source{0x12, 0x34, 0x56, 0x78, 0xff, 0x80, 0x00, 0x42, 0xaa, 0xbb, 0xcc, 0xdd};
            ui.present_surface(1, {.width = 2, .height = 1, .stride = 12, .format = format, .pixels = source.data()});
            ui.set_caret(1, RECT{-10, -20, 1, 30});
            EXPECT_EQ((std::vector<uint8_t>{0xed, 0xcb, 0xa9, 0x78, 0xff, 0x80, 0x00, 0x42, 0xaa, 0xbb, 0xcc, 0xdd}), ui.pixels);
            EXPECT_EQ(format, ui.desc.format);
            ui.set_caret(1, std::nullopt);
            EXPECT_EQ(source, ui.pixels);
            EXPECT_EQ(0x12, source.front());
        }
    }

    TEST_F(UiBackendTest, RepaintingAndMovingRestoreTheLatestUnderlyingPixels)
    {
        std::array<uint32_t, 2> source{0xff123456, 0xffabcdef};
        const ui_surface_desc desc{.width = 2, .height = 1, .stride = 8, .pixels = source.data()};
        ui.present_surface(1, desc);
        ui.set_caret(1, RECT{0, 0, 1, 1});
        source = {0xff010203, 0xff102030};
        ui.present_surface(1, desc);
        EXPECT_EQ((std::vector<uint8_t>{0xfc, 0xfd, 0xfe, 0xff, 0x30, 0x20, 0x10, 0xff}), ui.pixels);
        ui.set_caret(1, RECT{1, 0, 2, 1});
        EXPECT_EQ((std::vector<uint8_t>{0x03, 0x02, 0x01, 0xff, 0xcf, 0xdf, 0xef, 0xff}), ui.pixels);
        ui.set_caret(1, std::nullopt);
        EXPECT_EQ((std::vector<uint8_t>{0x03, 0x02, 0x01, 0xff, 0x30, 0x20, 0x10, 0xff}), ui.pixels);
        EXPECT_EQ((std::array<uint32_t, 2>{0xff010203, 0xff102030}), source);
    }

    TEST_F(UiBackendTest, BlinkingRestoresAndInvertsWithoutAccumulatingChanges)
    {
        const uint32_t pixel = 0xff123456;
        ui.set_caret(1, RECT{0, 0, 1, 1});
        ui.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        const auto visible = ui.pixels;
        now += std::chrono::milliseconds(529);
        ui.update_caret_blink();
        EXPECT_EQ(1u, ui.presentations);
        now += std::chrono::milliseconds(1);
        ui.update_caret_blink();
        EXPECT_EQ((std::vector<uint8_t>{0x56, 0x34, 0x12, 0xff}), ui.pixels);
        now += std::chrono::milliseconds(530);
        ui.update_caret_blink();
        EXPECT_EQ(visible, ui.pixels);
        EXPECT_EQ(3u, ui.presentations);
        ui.set_caret(1, std::nullopt);
        const auto hidden = ui.pixels;
        now += std::chrono::seconds(10);
        ui.update_caret_blink();
        EXPECT_EQ(hidden, ui.pixels);
        EXPECT_EQ(4u, ui.presentations);
    }

    TEST_F(UiBackendTest, EventsCanChangeTheCaretAfterBlinkUpdate)
    {
        const uint32_t pixel = 0xff123456;
        ui.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        ui.on_pump = [this] { this->ui.set_caret(1, RECT{0, 0, 1, 1}); };
        ui.update_caret_blink();
        ui.pump_events();
        EXPECT_EQ((std::vector<uint8_t>{0xa9, 0xcb, 0xed, 0xff}), ui.pixels);
        ui.on_pump = [this] { this->ui.set_caret(1, std::nullopt); };
        ui.update_caret_blink();
        ui.pump_events();
        EXPECT_EQ((std::vector<uint8_t>{0x56, 0x34, 0x12, 0xff}), ui.pixels);
    }

    TEST_F(UiBackendTest, DestroyAndResetDiscardSurfacesAndBlinkState)
    {
        const uint32_t pixel = 0xff123456;
        ui.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        ui.set_caret(1, RECT{0, 0, 1, 1});
        ui.destroy_window(1);
        ui.set_caret(1, RECT{0, 0, 1, 1});
        EXPECT_EQ(2u, ui.presentations);
        ui.reset();
        now += std::chrono::milliseconds(530);
        ui.update_caret_blink();
        EXPECT_EQ(2u, ui.presentations);
        ui.present_surface(1, {.width = 1, .height = 1, .stride = 4, .pixels = &pixel});
        EXPECT_EQ((std::vector<uint8_t>{0x56, 0x34, 0x12, 0xff}), ui.pixels);
    }
}
