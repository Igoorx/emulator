#include "emulation_test_utils.hpp"

#if defined(__APPLE__) || defined(__ANDROID__)
#include <signal.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <unistd.h>
#endif

#ifdef __ANDROID__
#include <memory_manager.hpp>

#include <array>
#endif

namespace sogen::test
{
    namespace
    {
        std::unique_ptr<x86_64_emulator> try_create_fex_emulator()
        {
            try
            {
                return create_x86_64_emulator(backend_type::fex);
            }
            catch (const std::exception&)
            {
                return {};
            }
        }

#if defined(__APPLE__) || defined(__ANDROID__)
        volatile sig_atomic_t previous_sigtrap_count = 0;
        volatile sig_atomic_t previous_sigtrap_on_expected_stack = 0;
        volatile uintptr_t expected_signal_stack_begin = 0;
        volatile uintptr_t expected_signal_stack_end = 0;
        volatile sig_atomic_t block_previous_sigtrap_handler = 0;
        int previous_sigtrap_entered_fd = -1;
        int previous_sigtrap_release_fd = -1;

        void previous_sigtrap_handler(int)
        {
            previous_sigtrap_count = previous_sigtrap_count + 1;

            const std::byte stack_marker{};
            const auto stack_address = reinterpret_cast<uintptr_t>(&stack_marker);
            previous_sigtrap_on_expected_stack = stack_address >= expected_signal_stack_begin && stack_address < expected_signal_stack_end;

            if (block_previous_sigtrap_handler != 0)
            {
                char byte = 0;
                ::write(previous_sigtrap_entered_fd, &byte, 1);
                ::read(previous_sigtrap_release_fd, &byte, 1);
            }
        }
#endif
    }

    TEST(FexRegisterTest, ExtendedGprSubRegisterReadsAliasFullRegister)
    {
        const auto emu = try_create_fex_emulator();
        if (!emu)
        {
            GTEST_SKIP() << "FEX backend is not available";
        }

        emu->reg(x86_register::r9, 0x1122334455667788ULL);
        EXPECT_EQ(emu->reg<uint32_t>(x86_register::r9d), 0x55667788U);
        EXPECT_EQ(emu->reg<uint16_t>(x86_register::r9w), 0x7788U);
        EXPECT_EQ(emu->reg<uint8_t>(x86_register::r9b), 0x88U);

        emu->reg(x86_register::r15, 0xCAFEBABE00C0FFEEULL);
        EXPECT_EQ(emu->reg<uint32_t>(x86_register::r15d), 0x00C0FFEEU);
        EXPECT_EQ(emu->reg<uint16_t>(x86_register::r15w), 0xFFEEU);
        EXPECT_EQ(emu->reg<uint8_t>(x86_register::r15b), 0xEEU);
    }

#ifdef __ANDROID__
    TEST(FexMemoryViolationTest, PlainGuestStoreToReadOnlyMemoryIsWrite)
    {
        const auto emu = try_create_fex_emulator();
        if (!emu)
        {
            GTEST_SKIP() << "FEX backend is not available";
        }

        memory_manager memory{*emu};
        constexpr size_t page_size = 0x1000;
        const uint64_t code = memory.allocate_memory(page_size, memory_permission::read_write);
        const uint64_t target = memory.allocate_memory(page_size, memory_permission::read_write);
        const uint64_t gdt = memory.allocate_memory(page_size, memory_permission::read_write);
        ASSERT_NE(code, 0u);
        ASSERT_NE(target, 0u);
        ASSERT_NE(gdt, 0u);

        constexpr uint16_t long_mode_code_selector = 0x08;
        constexpr uint64_t long_mode_code_descriptor = 0x00AF9B000000FFFF;
        emu->write_memory<uint64_t>(gdt + long_mode_code_selector, long_mode_code_descriptor);
        emu->load_gdt(gdt, page_size);
        emu->reg<uint16_t>(x86_register::cs, long_mode_code_selector);

        // mov [rax], rbx; hlt. The translated store is an ordinary guest store; the Android fault
        // classifier must not depend on the deliberately narrow STLR-family emulation decoder.
        constexpr std::array<uint8_t, 4> guest_code = {0x48, 0x89, 0x18, 0xF4};
        memory.write_memory(code, guest_code.data(), guest_code.size());
        ASSERT_TRUE(memory.protect_memory(code, page_size, memory_permission::read_exec));
        ASSERT_TRUE(memory.protect_memory(target, page_size, memory_permission::read));

        bool observed = false;
        uint64_t observed_address = 0;
        memory_operation observed_operation = memory_operation::read;
        memory_violation_type observed_type = memory_violation_type::unmapped;
        emu->hook_memory_violation(
            [&](cpu_interface& cpu, uint64_t address, size_t, memory_operation operation, memory_violation_type type) {
                observed = true;
                observed_address = address;
                observed_operation = operation;
                observed_type = type;
                cpu.stop();
                return memory_violation_continuation::stop;
            });

        emu->reg(x86_register::rip, code);
        emu->reg(x86_register::rax, target);
        emu->reg(x86_register::rbx, 0x1122334455667788ULL);
        emu->start(0);

        EXPECT_TRUE(observed);
        EXPECT_EQ(observed_address, target);
        EXPECT_EQ(observed_operation, memory_operation::write);
        EXPECT_EQ(observed_type, memory_violation_type::protection);
    }
#endif

#if defined(__APPLE__) || defined(__ANDROID__)
    TEST(FexSignalTest, UnhandledSignalChainsAndTeardownRestoresPreviousAction)
    {
        struct sigaction original_action{};
        ASSERT_EQ(::sigaction(SIGTRAP, nullptr, &original_action), 0);

        struct sigaction previous_action{};
        previous_action.sa_handler = previous_sigtrap_handler;
        sigemptyset(&previous_action.sa_mask);
        ASSERT_EQ(::sigaction(SIGTRAP, &previous_action, nullptr), 0);
        previous_sigtrap_count = 0;

        auto emu = try_create_fex_emulator();
        if (!emu)
        {
            ::sigaction(SIGTRAP, &original_action, nullptr);
            GTEST_SKIP() << "FEX backend is not available";
        }

        // No FEX thread exists yet, so this signal is intentionally unhandled by the backend and must
        // retain the embedding application's pre-existing disposition.
        EXPECT_EQ(::raise(SIGTRAP), 0);
        EXPECT_EQ(previous_sigtrap_count, 1);

        emu.reset();

        struct sigaction restored_action{};
        EXPECT_EQ(::sigaction(SIGTRAP, nullptr, &restored_action), 0);
        EXPECT_EQ(restored_action.sa_handler, previous_sigtrap_handler);

        ::sigaction(SIGTRAP, &original_action, nullptr);
    }

    TEST(FexSignalTest, UnhandledSignalOnUnrelatedThreadCanFinishDuringTeardown)
    {
        struct sigaction original_action{};
        ASSERT_EQ(::sigaction(SIGTRAP, nullptr, &original_action), 0);

        struct sigaction previous_action{};
        previous_action.sa_handler = previous_sigtrap_handler;
        sigemptyset(&previous_action.sa_mask);
        ASSERT_EQ(::sigaction(SIGTRAP, &previous_action, nullptr), 0);
        previous_sigtrap_count = 0;
        expected_signal_stack_begin = 0;
        expected_signal_stack_end = 0;

        int entered_pipe[2]{};
        int release_pipe[2]{};
        ASSERT_EQ(::pipe(entered_pipe), 0);
        ASSERT_EQ(::pipe(release_pipe), 0);
        previous_sigtrap_entered_fd = entered_pipe[1];
        previous_sigtrap_release_fd = release_pipe[0];
        block_previous_sigtrap_handler = 1;

        auto emu = try_create_fex_emulator();
        if (!emu)
        {
            block_previous_sigtrap_handler = 0;
            ::close(entered_pipe[0]);
            ::close(entered_pipe[1]);
            ::close(release_pipe[0]);
            ::close(release_pipe[1]);
            ::sigaction(SIGTRAP, &original_action, nullptr);
            GTEST_SKIP() << "FEX backend is not available";
        }

        int raise_result = -1;
        std::thread signal_thread([&raise_result] { raise_result = ::raise(SIGTRAP); });

        char byte = 0;
        EXPECT_EQ(::read(entered_pipe[0], &byte, 1), 1);
        emu.reset();
        EXPECT_EQ(::write(release_pipe[1], &byte, 1), 1);
        signal_thread.join();

        sigset_t joined_signal_mask{};
        ASSERT_EQ(::sigprocmask(SIG_SETMASK, nullptr, &joined_signal_mask), 0);
        EXPECT_EQ(sigismember(&joined_signal_mask, SIGTRAP), 0) << "SIGTRAP was blocked while joining the signal thread";

        block_previous_sigtrap_handler = 0;
        previous_sigtrap_entered_fd = -1;
        previous_sigtrap_release_fd = -1;
        ::close(entered_pipe[0]);
        ::close(entered_pipe[1]);
        ::close(release_pipe[0]);
        ::close(release_pipe[1]);

        EXPECT_EQ(raise_result, 0);
        EXPECT_EQ(previous_sigtrap_count, 1);

        ::sigaction(SIGTRAP, &original_action, nullptr);
    }

    TEST(FexSignalTest, PreviousOnStackHandlerUsesApplicationAlternateStack)
    {
        struct sigaction original_action{};
        ASSERT_EQ(::sigaction(SIGTRAP, nullptr, &original_action), 0);

        stack_t original_stack{};
        ASSERT_EQ(::sigaltstack(nullptr, &original_stack), 0);

        constexpr size_t application_alt_stack_size = 64 * 1024;
        const auto application_alt_stack = std::make_unique<std::byte[]>(application_alt_stack_size);
        stack_t application_stack{};
        application_stack.ss_sp = application_alt_stack.get();
        application_stack.ss_size = application_alt_stack_size;
        ASSERT_EQ(::sigaltstack(&application_stack, nullptr), 0);

        struct sigaction previous_action{};
        previous_action.sa_handler = previous_sigtrap_handler;
        previous_action.sa_flags = SA_ONSTACK;
        sigemptyset(&previous_action.sa_mask);
        ASSERT_EQ(::sigaction(SIGTRAP, &previous_action, nullptr), 0);

        previous_sigtrap_count = 0;
        previous_sigtrap_on_expected_stack = 0;
        expected_signal_stack_begin = reinterpret_cast<uintptr_t>(application_alt_stack.get());
        expected_signal_stack_end = expected_signal_stack_begin + application_alt_stack_size;

        auto emu = try_create_fex_emulator();
        const bool backend_available = emu != nullptr;
        if (emu)
        {
            struct sigaction emulator_action{};
            ASSERT_EQ(::sigaction(SIGTRAP, nullptr, &emulator_action), 0);
            EXPECT_NE(emulator_action.sa_handler, previous_sigtrap_handler);
            EXPECT_NE(emulator_action.sa_flags & SA_SIGINFO, 0);

            stack_t emulator_stack{};
            ASSERT_EQ(::sigaltstack(nullptr, &emulator_stack), 0);
            EXPECT_EQ(emulator_stack.ss_sp, application_stack.ss_sp);
            EXPECT_EQ(emulator_stack.ss_size, application_stack.ss_size);

            EXPECT_EQ(::raise(SIGTRAP), 0);
            EXPECT_EQ(previous_sigtrap_count, 1);
            EXPECT_EQ(previous_sigtrap_on_expected_stack, 1);
            emu.reset();

            stack_t restored_stack{};
            EXPECT_EQ(::sigaltstack(nullptr, &restored_stack), 0);
            EXPECT_EQ(restored_stack.ss_sp, application_stack.ss_sp);
            EXPECT_EQ(restored_stack.ss_size, application_stack.ss_size);
        }

        expected_signal_stack_begin = 0;
        expected_signal_stack_end = 0;
        ::sigaction(SIGTRAP, &original_action, nullptr);
        ::sigaltstack(&original_stack, nullptr);

        if (!backend_available)
        {
            GTEST_SKIP() << "FEX backend is not available";
        }
    }
#endif

    TEST(FexRegisterTest, ExtendedGprSubRegisterWrites)
    {
        const auto emu = try_create_fex_emulator();
        if (!emu)
        {
            GTEST_SKIP() << "FEX backend is not available";
        }

        emu->reg(x86_register::r9, 0x1122334455667788ULL);

        emu->reg<uint8_t>(x86_register::r9b, 0xAA);
        EXPECT_EQ(emu->reg(x86_register::r9), 0x11223344556677AAULL);

        emu->reg<uint16_t>(x86_register::r9w, 0xBBCC);
        EXPECT_EQ(emu->reg(x86_register::r9), 0x112233445566BBCCULL);

        emu->reg<uint32_t>(x86_register::r9d, 0xDDEEFF00U);
        EXPECT_EQ(emu->reg(x86_register::r9), 0x00000000DDEEFF00ULL);
    }
} // namespace sogen::test
