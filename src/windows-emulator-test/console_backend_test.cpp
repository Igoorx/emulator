#include <console_backends/buffered_console_backend.hpp>

#include <gtest/gtest.h>

namespace sogen::test
{
    namespace
    {
        class queued_console_backend final : public buffered_console_backend
        {
          public:
            void queue(const std::string_view input)
            {
                this->input_.insert(this->input_.end(), input.begin(), input.end());
            }

            void set_input_mode(const console_input_mode& mode) override
            {
                mode_ = mode;
            }

            console_input_mode mode_{};

          protected:
            void refill(int /*timeout_ms*/) override
            {
            }
        };
    }

    TEST(ConsoleBackendTest, EventsAndByteReadsShareBufferedInput)
    {
        queued_console_backend console{};
        console.queue("\x1B[Aq");

        ASSERT_TRUE(console.input_available());
        const auto event = console.read_input_event();
        ASSERT_TRUE(event.has_value());
        EXPECT_EQ(event->key, console_key::up);
        EXPECT_EQ(console.read_input(1), "q");
        EXPECT_FALSE(console.input_available());
    }

    TEST(ConsoleBackendTest, DecodesEnterAndDownNavigation)
    {
        queued_console_backend console{};
        console.queue("\r\x1B[B");

        const auto enter = console.read_input_event();
        ASSERT_TRUE(enter.has_value());
        EXPECT_EQ(enter->key, console_key::enter);
        EXPECT_EQ(enter->character, u'\r');

        const auto down = console.read_input_event();
        ASSERT_TRUE(down.has_value());
        EXPECT_EQ(down->key, console_key::down);
    }

} // namespace sogen::test
