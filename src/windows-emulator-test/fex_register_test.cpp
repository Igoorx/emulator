#include "emulation_test_utils.hpp"

#ifdef __ANDROID__
#include <memory_manager.hpp>
#include <signal.h>

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

#ifdef __ANDROID__
        volatile sig_atomic_t previous_sigtrap_count = 0;

        void previous_sigtrap_handler(int)
        {
            previous_sigtrap_count = previous_sigtrap_count + 1;
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
        ASSERT_NE(code, 0u);
        ASSERT_NE(target, 0u);

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
        emu->hook_memory_violation([&](cpu_interface& cpu, uint64_t address, size_t, memory_operation operation,
                                       memory_violation_type type) {
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
