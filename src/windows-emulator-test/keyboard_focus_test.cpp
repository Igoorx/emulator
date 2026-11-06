#include "emulation_test_utils.hpp"
#include <syscall_utils.hpp>

namespace sogen::syscalls
{
    BOOL handle_NtUserCreateCaret(const syscall_context& c, hwnd window, uint64_t bitmap, int32_t width, int32_t height);
    BOOL handle_NtUserDestroyCaret(const syscall_context& c);
    BOOL handle_NtUserSetCaretPos(const syscall_context& c, int32_t x, int32_t y);
    BOOL handle_NtUserShowCaret(const syscall_context& c, hwnd window);
    BOOL handle_NtUserHideCaret(const syscall_context& c, hwnd window);
    BOOL handle_NtUserMoveWindow(const syscall_context& c, hwnd window, int x, int y, int width, int height, BOOL repaint);
}

namespace sogen::test
{
    namespace
    {
        class recording_ui_backend : public ui_backend
        {
          public:
            void set_event_sink(event_sink) override
            {
            }

            void pump_events() override
            {
            }

            void set_caret(const hwnd target, const std::optional<RECT>& rect) override
            {
                this->window = target;
                this->caret = rect;
            }

            hwnd window{};
            std::optional<RECT> caret{};
        };

        class KeyboardFocusTest : public testing::Test
        {
          protected:
            void SetUp() override
            {
                emulator_interfaces interfaces{};
                auto backend = std::make_unique<recording_ui_backend>();
                this->ui = backend.get();
                interfaces.ui = std::move(backend);
                interfaces.audio = std::make_unique<null_audio_backend>();
                interfaces.console = std::make_unique<null_console_backend>();
                emu = std::make_unique<windows_emulator>(
                    create_x86_64_emulator_from_environment(),
                    emulator_settings{.disable_logging = true, .emulation_root = get_emulator_root(), .load_registry = false},
                    emulator_callbacks{}, std::move(interfaces));
                const auto base = emu->memory.allocate_memory(0x10000, memory_permission::read_write);
                emu->process.base_allocator = emulator_allocator{emu->memory, base, 0x10000};
                emu->process.user_handles.setup(false);
                const auto thread_handle =
                    emu->process.threads.store(emulator_thread{emu->memory, emu->process, 0, 0, 0x100000, 0, 8, true});
                thread = emu->process.threads.get(thread_handle);
                emu->vcpu(0).active_thread = thread;
                auto [parent_handle, parent_window] = emu->process.windows.create(emu->memory);
                parent = parent_handle.bits;
                parent_window.handle = parent;
                parent_window.thread_id = thread->id;
                auto [child_handle, child_window] = emu->process.windows.create(emu->memory);
                child = child_handle.bits;
                child_window.handle = child;
                child_window.thread_id = thread->id;
                child_window.parent_handle = parent;
                thread->set_focus_window(child);
            }

            std::unique_ptr<windows_emulator> emu{};
            emulator_thread* thread{};
            hwnd parent{};
            hwnd child{};
            recording_ui_backend* ui{};
        };
    }

    TEST_F(KeyboardFocusTest, HostKeyboardAndCharacterMessagesReachTheFocusedChild)
    {
        emu->handle_ui_event({.window = parent, .message = WM_KEYDOWN, .wParam = 'A'});
        emu->handle_ui_event({.window = parent, .message = WM_CHAR, .wParam = 'a'});
        emu->handle_ui_event({.window = parent, .message = WM_KEYUP, .wParam = 'A'});

        ASSERT_EQ(3u, thread->message_queue.size());
        for (const auto& message : thread->message_queue)
        {
            EXPECT_EQ(child, message.window);
        }
        EXPECT_EQ(WM_KEYDOWN, thread->message_queue[0].message);
        EXPECT_EQ(WM_CHAR, thread->message_queue[1].message);
        EXPECT_EQ('a', thread->message_queue[1].wParam);
        EXPECT_EQ(WM_KEYUP, thread->message_queue[2].message);
    }

    TEST_F(KeyboardFocusTest, InputFallsBackToItsWindowWhenNothingHasFocus)
    {
        thread->set_focus_window(0);
        emu->handle_ui_event({.window = parent, .message = WM_CHAR, .wParam = 'a'});
        ASSERT_EQ(1u, thread->message_queue.size());
        EXPECT_EQ(parent, thread->message_queue.front().window);
    }

    TEST_F(KeyboardFocusTest, CaretFollowsItsWindowAndAncestorsWithoutBecomingVisibleWhenHidden)
    {
        auto* win = emu->process.windows.get(child);
        win->style = WS_CHILD | WS_VISIBLE;
        win->x = 20;
        win->y = 30;
        auto [caret_handle, caret_window] = emu->process.windows.create(emu->memory);
        const auto caret_owner = caret_handle.bits;
        caret_window.handle = caret_owner;
        caret_window.thread_id = thread->id;
        caret_window.parent_handle = child;
        caret_window.style = WS_CHILD | WS_VISIBLE;
        caret_window.x = 10;
        caret_window.y = 15;
        const syscall_context c{.win_emu = *emu, .emu = emu->vcpu(0).cpu, .vcpu = emu->vcpu(0), .proc = emu->process};

        ASSERT_TRUE(syscalls::handle_NtUserCreateCaret(c, caret_owner, 0, 1, 12));
        ASSERT_TRUE(syscalls::handle_NtUserSetCaretPos(c, 5, 7));
        ASSERT_TRUE(syscalls::handle_NtUserShowCaret(c, caret_owner));
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(35, ui->caret->left);
        EXPECT_EQ(52, ui->caret->top);

        ASSERT_TRUE(syscalls::handle_NtUserMoveWindow(c, caret_owner, 40, 50, 100, 100, FALSE));
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(parent, ui->window);
        EXPECT_EQ(65, ui->caret->left);
        EXPECT_EQ(87, ui->caret->top);
        EXPECT_EQ(66, ui->caret->right);
        EXPECT_EQ(99, ui->caret->bottom);

        ASSERT_TRUE(syscalls::handle_NtUserMoveWindow(c, child, 100, 100, 200, 200, FALSE));
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(parent, ui->window);
        EXPECT_EQ(145, ui->caret->left);
        EXPECT_EQ(157, ui->caret->top);
        EXPECT_EQ(146, ui->caret->right);
        EXPECT_EQ(169, ui->caret->bottom);

        ASSERT_TRUE(syscalls::handle_NtUserMoveWindow(c, parent, 300, 400, 500, 500, FALSE));
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(145, ui->caret->left);
        EXPECT_EQ(157, ui->caret->top);

        ASSERT_TRUE(syscalls::handle_NtUserHideCaret(c, caret_owner));
        ASSERT_TRUE(syscalls::handle_NtUserMoveWindow(c, child, 200, 250, 200, 200, FALSE));
        EXPECT_FALSE(ui->caret.has_value());
        ASSERT_TRUE(syscalls::handle_NtUserShowCaret(c, caret_owner));
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(245, ui->caret->left);
        EXPECT_EQ(307, ui->caret->top);
    }

    TEST_F(KeyboardFocusTest, CaretVisibilityIsNestedAndPositionIsRelativeToItsWindow)
    {
        auto* win = emu->process.windows.get(child);
        win->style = WS_CHILD | WS_VISIBLE;
        win->x = 20;
        win->y = 30;
        const syscall_context c{.win_emu = *emu, .emu = emu->vcpu(0).cpu, .vcpu = emu->vcpu(0), .proc = emu->process};

        ASSERT_TRUE(syscalls::handle_NtUserCreateCaret(c, child, 0, 1, 12));
        ASSERT_TRUE(syscalls::handle_NtUserSetCaretPos(c, 5, 7));
        EXPECT_FALSE(ui->caret.has_value());
        ASSERT_TRUE(syscalls::handle_NtUserShowCaret(c, child));
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(parent, ui->window);
        EXPECT_EQ(25, ui->caret->left);
        EXPECT_EQ(37, ui->caret->top);
        EXPECT_EQ(26, ui->caret->right);
        EXPECT_EQ(49, ui->caret->bottom);

        ui->caret.reset();
        emu->process.restore_windows_after_state_restore(*emu);
        ASSERT_TRUE(ui->caret.has_value());
        EXPECT_EQ(25, ui->caret->left);
        EXPECT_EQ(37, ui->caret->top);

        ASSERT_TRUE(syscalls::handle_NtUserHideCaret(c, child));
        ASSERT_TRUE(syscalls::handle_NtUserHideCaret(c, child));
        ASSERT_TRUE(syscalls::handle_NtUserShowCaret(c, child));
        EXPECT_FALSE(ui->caret.has_value());
        ASSERT_TRUE(syscalls::handle_NtUserShowCaret(c, child));
        EXPECT_TRUE(ui->caret.has_value());
        EXPECT_FALSE(syscalls::handle_NtUserHideCaret(c, parent));
        ASSERT_TRUE(syscalls::handle_NtUserDestroyCaret(c));
        EXPECT_FALSE(ui->caret.has_value());
    }
}
