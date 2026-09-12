#include "../std_include.hpp"
#include "sspi_rpc.hpp"

#include "binary_writer.hpp"
#include "../windows_emulator.hpp"

namespace sogen
{

    namespace
    {
        constexpr std::array<uint8_t, 16> k_sspi_rpc_interface = {0xc8, 0xad, 0x32, 0x4f, 0x52, 0x60, 0x04, 0x4a,
                                                                  0x87, 0x01, 0x29, 0x3c, 0xcf, 0x20, 0x96, 0xf0};
        constexpr std::array<uint8_t, 16> k_sspi_context_uuid = {0x53, 0x6f, 0x67, 0x65, 0x6e, 0x53, 0x73, 0x70,
                                                                 0x69, 0x43, 0x74, 0x78, 0x00, 0x00, 0x00, 0x01};
        constexpr std::array<uint8_t, 20> k_sspi_context_handle = {0x00, 0x00, 0x00, 0x00, 0x53, 0x6f, 0x67, 0x65, 0x6e, 0x53,
                                                                   0x73, 0x70, 0x69, 0x43, 0x74, 0x78, 0x00, 0x00, 0x00, 0x01};
        constexpr std::array<uint8_t, 32> k_sspi_connect_reply_body = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                       0x00, 0x53, 0x6f, 0x67, 0x65, 0x6e, 0x53, 0x73, 0x70, 0x69, 0x43,
                                                                       0x74, 0x78, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
        static_assert(k_sspi_connect_reply_body.size() == 32);
        constexpr uint64_t k_sspi_credential_lower = 9;
        constexpr uint64_t k_sspi_credential_upper = 0x104f0;
        constexpr uint64_t k_sspi_credential_expiry = 0x7fffff36d5969fffULL;
        constexpr std::array<uint8_t, 16> k_sspi_credential_handle = {
            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        };

        std::string sspi_hex_dump(const uint8_t* data, const size_t length)
        {
            constexpr char hex_digits[] = "0123456789abcdef";
            std::string result;
            result.reserve(length * 3);
            for (size_t i = 0; i < length; ++i)
            {
                if (i != 0)
                {
                    result.push_back(' ');
                }
                result.push_back(hex_digits[data[i] >> 4]);
                result.push_back(hex_digits[data[i] & 0x0f]);
            }
            return result;
        }

        struct sspi_rpc_port : rpc_port
        {
            NTSTATUS handle_rpc(windows_emulator& win_emu, const uint32_t procedure_id, const lpc_request_context& c,
                                utils::aligned_binary_writer& writer, std::vector<alpc_reply_handle>& /*reply_handles*/) override
            {
                if (this->bound_interface() != k_sspi_rpc_interface)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (procedure_id == 0)
                {
                    return handle_connect_rpc(win_emu, c, writer);
                }

                if (!this->post_connect_operation_captured_)
                {
                    this->post_connect_operation_captured_ = true;
                    log_post_connect_operation(win_emu, procedure_id, c);
                }

                switch (procedure_id)
                {
                case 3:
                    return handle_call_rpc(win_emu, c, writer);

                case 4:
                    return handle_acquire_credentials(win_emu, c, writer);

                case 5:
                    return handle_free_credentials(win_emu, c, writer);

                case 6:
                    return handle_process_security_context_diagnostic(win_emu, c);
                default:
                    return STATUS_NOT_SUPPORTED;
                }
            }

          private:
            static void log_post_connect_operation(windows_emulator& win_emu, const uint32_t procedure_id, const lpc_request_context& c)
            {
                const auto dump_length = std::min<size_t>(c.send_buffer_length, 256);
                std::vector<uint8_t> request(dump_length);
                if (!request.empty())
                {
                    win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());
                }

                bool context_handle_round_tripped = false;
                if (procedure_id == 4 && c.send_buffer_length >= k_sspi_context_handle.size())
                {
                    std::array<uint8_t, k_sspi_context_handle.size()> context_handle{};
                    win_emu.emu().read_memory(c.send_buffer, context_handle.data(), context_handle.size());
                    context_handle_round_tripped =
                        std::memcmp(context_handle.data(), k_sspi_context_handle.data(), k_sspi_context_handle.size()) == 0;
                }

                win_emu.log.print(color::gray, "SSPI_RPC post_connect procedure_id=" + std::to_string(procedure_id) +
                                                   " request_length=" + std::to_string(c.send_buffer_length) +
                                                   " context_handle_round_tripped=" + (context_handle_round_tripped ? "yes" : "no") + "\n");
                win_emu.log.print(color::gray, "SSPI_RPC post_connect_body=" + sspi_hex_dump(request.data(), request.size()) + "\n");

                if (procedure_id != 3)
                {
                    return;
                }

                const auto read_u16 = [&request](const size_t offset) {
                    uint16_t value{};
                    if (offset + sizeof(value) <= request.size())
                    {
                        std::memcpy(&value, request.data() + offset, sizeof(value));
                    }
                    return value;
                };
                const auto read_u32 = [&request](const size_t offset) {
                    uint32_t value{};
                    if (offset + sizeof(value) <= request.size())
                    {
                        std::memcpy(&value, request.data() + offset, sizeof(value));
                    }
                    return value;
                };
                const auto read_u64 = [&request](const size_t offset) {
                    uint64_t value{};
                    if (offset + sizeof(value) <= request.size())
                    {
                        std::memcpy(&value, request.data() + offset, sizeof(value));
                    }
                    return value;
                };

                const auto context_attributes = read_u32(0);
                const auto declared_length = read_u32(0x14);
                const auto conformant_count = read_u64(0x18);
                const bool context_handle_round_trip =
                    request.size() >= k_sspi_context_handle.size() &&
                    std::memcmp(request.data(), k_sspi_context_handle.data(), k_sspi_context_handle.size()) == 0;
                const bool ndr_envelope_valid =
                    request.size() >= 0x20 && c.send_buffer_length == 0xf8 && declared_length == 0xd8 && conformant_count == 0xd8;

                std::string context_uuid = request.size() >= k_sspi_context_handle.size()
                                               ? sspi_hex_dump(request.data() + 4, k_sspi_context_uuid.size())
                                               : "unavailable";
                std::string spm_length = "unavailable";
                std::string spm_header = "unavailable";
                std::string spm_size_field = "unavailable";
                std::string spm_api = "unavailable";
                std::string package_index = "unavailable";
                std::string spm_0x30_raw = "unavailable";
                std::string spm_0x38_raw = "unavailable";
                if (ndr_envelope_valid)
                {
                    spm_length = std::to_string(declared_length);
                    spm_header = std::to_string(read_u32(0x20));
                    spm_size_field = std::to_string(read_u16(0x22));
                    spm_api = std::to_string(read_u32(0x48));
                    package_index = std::to_string(read_u64(0x60));
                    spm_0x30_raw = sspi_hex_dump(request.data() + 0x50, sizeof(uint64_t));
                    spm_0x38_raw = sspi_hex_dump(request.data() + 0x58, sizeof(uint64_t));
                }

                win_emu.log.print(
                    color::gray,
                    "SSPI_RPC SspirCallRpc procedure_id=3 body_length=" + std::to_string(c.send_buffer_length) +
                        " context_attributes=" + std::to_string(context_attributes) + " context_uuid=" + context_uuid +
                        " context_handle_round_tripped=" + (context_handle_round_trip ? "yes" : "no") +
                        " declared_length=" + std::to_string(declared_length) + " conformant_count=" + std::to_string(conformant_count) +
                        " envelope_valid=" + (ndr_envelope_valid ? "yes" : "no") + " spm_length=" + spm_length +
                        " spm_header=" + spm_header + " spm_size_field=" + spm_size_field + " spm_api=" + spm_api +
                        " package_index=" + package_index + " spm_0x30_raw=" + spm_0x30_raw + " spm_0x38_raw=" + spm_0x38_raw + "\n");
                win_emu.log.print(color::gray, "SSPI_RPC SspirCallRpc_body=" + sspi_hex_dump(request.data(), request.size()) + "\n");
                if (ndr_envelope_valid)
                {
                    win_emu.log.print(color::gray,
                                      "SSPI_RPC SspirCallRpc_spm=" + sspi_hex_dump(request.data() + 0x20, declared_length) + "\n");
                }
            }

            NTSTATUS handle_call_rpc(windows_emulator& win_emu, const lpc_request_context& c, utils::aligned_binary_writer& writer)
            {
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64 || c.send_buffer == 0 ||
                    c.send_buffer_length != 0xf8)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                std::array<uint8_t, 0xf8> request{};
                win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());

                const auto read_u32 = [&request](const size_t offset) {
                    uint32_t value{};
                    std::memcpy(&value, request.data() + offset, sizeof(value));
                    return value;
                };
                const auto read_u64 = [&request](const size_t offset) {
                    uint64_t value{};
                    std::memcpy(&value, request.data() + offset, sizeof(value));
                    return value;
                };

                const bool context_handle_round_tripped =
                    std::memcmp(request.data(), k_sspi_context_handle.data(), k_sspi_context_handle.size()) == 0;
                if (!context_handle_round_tripped || read_u32(0x14) != 0xd8 || read_u64(0x18) != 0xd8 || read_u32(0x20 + 0x28) != 4 ||
                    read_u64(0x20 + 0x40) != 0)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (writer.offset() != 0x18)
                {
                    win_emu.log.warn("[sspi-rpc] unexpected GetBinding RPC header size: 0x%llX\n",
                                     static_cast<unsigned long long>(writer.offset()));
                    return STATUS_INVALID_PARAMETER;
                }

                constexpr std::u16string_view package_name = u"Microsoft Unified Security Protocol Provider";
                constexpr std::u16string_view package_comment = u"Schannel Security Package";
                constexpr std::u16string_view module_name = u"C:\\Windows\\system32\\schannel.DLL";
                static_assert(package_name.size() * sizeof(char16_t) == 0x58);
                static_assert(package_comment.size() * sizeof(char16_t) == 0x32);
                static_assert(module_name.size() * sizeof(char16_t) == 0x40);

                if (this->diagnostic_strings_ == 0)
                {
                    this->diagnostic_strings_ = win_emu.memory.allocate_memory(0x1000, nt_memory_permission{memory_permission::read_write});
                    if (this->diagnostic_strings_ == 0)
                    {
                        return STATUS_NO_MEMORY;
                    }

                    std::array<uint8_t, 0xd0> string_blob{};
                    std::memcpy(string_blob.data() + 0x000, package_name.data(), 0x58);
                    std::memcpy(string_blob.data() + 0x05a, package_comment.data(), 0x32);
                    std::memcpy(string_blob.data() + 0x08e, module_name.data(), 0x40);
                    win_emu.emu().write_memory(this->diagnostic_strings_, string_blob.data(), string_blob.size());
                }

                const uint64_t strings_base = this->diagnostic_strings_;
                const uint64_t package_name_ptr = strings_base + 0x000;
                const uint64_t package_comment_ptr = strings_base + 0x05a;
                const uint64_t module_name_ptr = strings_base + 0x08e;

                std::array<uint8_t, 0xd8> spm{};
                win_emu.emu().read_memory(c.send_buffer + 0x20, spm.data(), spm.size());
                std::fill(spm.begin() + 0x48, spm.end(), uint8_t{0});

                const auto put16 = [&spm](const size_t offset, const uint16_t value) {
                    std::memcpy(spm.data() + offset, &value, sizeof(value));
                };
                const auto put32 = [&spm](const size_t offset, const uint32_t value) {
                    std::memcpy(spm.data() + offset, &value, sizeof(value));
                };
                const auto put64 = [&spm](const size_t offset, const uint64_t value) {
                    std::memcpy(spm.data() + offset, &value, sizeof(value));
                };

                put16(0x48, 0x58);
                put16(0x4a, 0x5a);
                put64(0x50, package_name_ptr);

                put16(0x58, 0x32);
                put16(0x5a, 0x34);
                put64(0x60, package_comment_ptr);

                put16(0x68, 0x40);
                put16(0x6a, 0x42);
                put64(0x70, module_name_ptr);

                put32(0x78, 1);
                put32(0x7c, 0x004107b3);
                put32(0x80, 0);
                put32(0x84, 14);
                put32(0x88, 1);
                put32(0x8c, 0x6000);
                put32(0x90, 14);

                constexpr std::array<uint32_t, 16> context_thunks = {
                    6, 89, 84, 82, 91, 94, 102, 34, 103, 104, 113, 107, 117, 0x00c10076, 0, 0,
                };
                for (size_t i = 0; i < context_thunks.size(); ++i)
                {
                    put32(0x94 + i * sizeof(uint32_t), context_thunks[i]);
                }
                put32(0xd4, 0);

                const auto procedure_start = writer.offset();
                writer.write<int32_t>(0xd8);
                writer.write_ndr_pointer(true);
                writer.write_pointer_sized(0xd8);
                writer.write(spm.data(), spm.size(), 1);
                writer.write<uint32_t>(0);
                writer.write_pointer_sized(0);
                writer.write_pointer_sized(0);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(0);
                writer.write_ndr_pointer(false);
                writer.write<int8_t>(0);
                writer.align_to(8);
                writer.write<int32_t>(0);
                writer.align_to(8);
                writer.pad(0x18);

                const auto procedure_size = writer.offset() - procedure_start;
                if (procedure_size != 0x140 || writer.offset() != 0x158)
                {
                    win_emu.log.warn("[sspi-rpc] malformed GetBinding reply: procedure=0x%llX payload=0x%llX\n",
                                     static_cast<unsigned long long>(procedure_size), static_cast<unsigned long long>(writer.offset()));
                    return STATUS_INVALID_PARAMETER;
                }

                win_emu.log.print(color::gray,
                                  "[sspi-rpc] GetBinding Windows-reference reply\n"
                                  "request_package_id=0\n"
                                  "strings_base=0x%llx\n"
                                  "package_name_ptr=0x%llx\n"
                                  "comment_ptr=0x%llx\n"
                                  "module_ptr=0x%llx\n"
                                  "PackageIndex=1\n"
                                  "fCapabilities=0x004107b3\n"
                                  "Flags=0\n"
                                  "RpcId=14\n"
                                  "Version=1\n"
                                  "TokenSize=0x6000\n"
                                  "ContextThunksCount=14\n"
                                  "spm_size=0xd8\n"
                                  "callback_offset=0xf0\n"
                                  "procedure_return_offset=0x120\n"
                                  "procedure_body_size=0x140\n"
                                  "rpc_payload_size=0x158\n",
                                  static_cast<unsigned long long>(strings_base), static_cast<unsigned long long>(package_name_ptr),
                                  static_cast<unsigned long long>(package_comment_ptr), static_cast<unsigned long long>(module_name_ptr));

                return STATUS_SUCCESS;
            }

            NTSTATUS handle_acquire_credentials(windows_emulator& win_emu, const lpc_request_context& c,
                                                utils::aligned_binary_writer& writer)
            {
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (!c.send_buffer || c.send_buffer_length < k_sspi_context_handle.size())
                {
                    return STATUS_INVALID_PARAMETER;
                }

                std::array<uint8_t, k_sspi_context_handle.size()> context_handle{};
                win_emu.emu().read_memory(c.send_buffer, context_handle.data(), context_handle.size());
                if (context_handle != k_sspi_context_handle)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                constexpr size_t max_sspi_rpc_dump = 0x1000;
                const auto dump_length = std::min<size_t>(c.send_buffer_length, max_sspi_rpc_dump);
                std::vector<uint8_t> request(dump_length);
                if (!request.empty())
                {
                    win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());
                }

                win_emu.log.print(color::gray, "SSPI_RPC procedure_id=4 body_length=" + std::to_string(c.send_buffer_length) +
                                                   " captured_length=" + std::to_string(request.size()) + "\n");
                constexpr size_t dump_chunk_size = 64;
                for (size_t offset = 0; offset < request.size(); offset += dump_chunk_size)
                {
                    const auto chunk_length = std::min(dump_chunk_size, request.size() - offset);
                    win_emu.log.print(color::gray, "SSPI_RPC procedure_4_body offset=" + std::to_string(offset) +
                                                       " data=" + sspi_hex_dump(request.data() + offset, chunk_length) + "\n");
                }

                if (writer.offset() != 0x18)
                {
                    win_emu.log.warn("[sspi-rpc] unexpected op4 RPC header size: 0x%llX\n",
                                     static_cast<unsigned long long>(writer.offset()));
                    return STATUS_INVALID_PARAMETER;
                }

                const auto procedure_start = writer.offset();
                writer.write<uint64_t>(k_sspi_credential_lower);
                writer.write<uint64_t>(k_sspi_credential_upper);
                writer.write<uint64_t>(k_sspi_credential_expiry);
                writer.write<uint32_t>(0);
                writer.write_pointer_sized(0);
                writer.write_pointer_sized(0);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(0);
                writer.write_ndr_pointer(false);
                writer.write<int8_t>(0);
                writer.align_to(8);
                writer.write<int32_t>(0);
                writer.align_to(8);
                writer.pad(0x50);

                const auto procedure_size = writer.offset() - procedure_start;
                if (procedure_size != 0xa0 || writer.offset() != 0xb8)
                {
                    win_emu.log.warn("[sspi-rpc] malformed AcquireCredentials reply: procedure=0x%llX payload=0x%llX\n",
                                     static_cast<unsigned long long>(procedure_size), static_cast<unsigned long long>(writer.offset()));
                    return STATUS_INVALID_PARAMETER;
                }

                win_emu.log.print(color::gray,
                                  "[sspi-rpc] AcquireCredentials Windows-reference reply\n"
                                  "credential_lower=0x%llx\n"
                                  "credential_upper=0x%llx\n"
                                  "expiry=0x%llx\n"
                                  "callback_offset=0x18\n"
                                  "procedure_return_offset=0x48\n"
                                  "procedure_body_size=0xa0\n"
                                  "rpc_payload_size=0xb8\n",
                                  static_cast<unsigned long long>(k_sspi_credential_lower),
                                  static_cast<unsigned long long>(k_sspi_credential_upper),
                                  static_cast<unsigned long long>(k_sspi_credential_expiry));

                return STATUS_SUCCESS;
            }

            NTSTATUS handle_free_credentials(windows_emulator& win_emu, const lpc_request_context& c, utils::aligned_binary_writer& writer)
            {
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (!c.send_buffer || c.send_buffer_length < k_sspi_context_handle.size())
                {
                    return STATUS_INVALID_PARAMETER;
                }

                std::array<uint8_t, k_sspi_context_handle.size()> context_handle{};
                win_emu.emu().read_memory(c.send_buffer, context_handle.data(), context_handle.size());
                if (context_handle != k_sspi_context_handle)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                std::vector<uint8_t> request(c.send_buffer_length);
                win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());

                std::optional<size_t> credential_offset;
                const auto full_handle_it =
                    std::search(request.begin(), request.end(), k_sspi_credential_handle.begin(), k_sspi_credential_handle.end());
                if (full_handle_it != request.end())
                {
                    credential_offset = static_cast<size_t>(std::distance(request.begin(), full_handle_it));
                }
                else
                {
                    const auto upper_handle_it =
                        std::search(request.begin(), request.end(), k_sspi_credential_handle.begin() + 8, k_sspi_credential_handle.end());
                    if (upper_handle_it != request.end())
                    {
                        credential_offset = static_cast<size_t>(std::distance(request.begin(), upper_handle_it));
                    }
                }

                win_emu.log.print(color::gray, "SSPI_RPC procedure_id=5 body_length=" + std::to_string(c.send_buffer_length) +
                                                   " credential_handle_round_tripped=" + (credential_offset ? "yes" : "no") +
                                                   " credential_handle_offset=" +
                                                   (credential_offset ? std::to_string(*credential_offset) : std::string{"unavailable"}) +
                                                   "\n");

                if (!credential_offset)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                if (writer.offset() != 0x18)
                {
                    win_emu.log.warn("[sspi-rpc] unexpected op5 RPC header size: 0x%llX\n",
                                     static_cast<unsigned long long>(writer.offset()));
                    return STATUS_INVALID_PARAMETER;
                }

                const auto procedure_start = writer.offset();
                writer.write<uint32_t>(0);
                writer.write_pointer_sized(0);
                writer.write_pointer_sized(0);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(0);
                writer.write_ndr_pointer(false);
                writer.write<int8_t>(0);
                writer.align_to(8);
                writer.write<int32_t>(0);
                writer.align_to(8);

                const auto procedure_size = writer.offset() - procedure_start;
                if (procedure_size != 0x38 || writer.offset() != 0x50)
                {
                    win_emu.log.warn("[sspi-rpc] malformed FreeCredentials reply: procedure=0x%llX payload=0x%llX\n",
                                     static_cast<unsigned long long>(procedure_size), static_cast<unsigned long long>(writer.offset()));
                    return STATUS_INVALID_PARAMETER;
                }

                win_emu.log.print(color::gray, "[sspi-rpc] FreeCredentials Windows-reference reply\n"
                                               "procedure_body_size=0x38\n"
                                               "rpc_payload_size=0x50\n");
                return STATUS_SUCCESS;
            }

            NTSTATUS handle_process_security_context_diagnostic(windows_emulator& win_emu, const lpc_request_context& c)
            {
                constexpr size_t max_sspi_rpc_dump = 0x4000;
                const auto dump_length = std::min<size_t>(c.send_buffer_length, max_sspi_rpc_dump);
                std::vector<uint8_t> request(dump_length);
                if (c.send_buffer && !request.empty())
                {
                    win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());
                }

                std::optional<size_t> credential_offset;
                if (request.size() >= k_sspi_credential_handle.size())
                {
                    const auto it =
                        std::search(request.begin(), request.end(), k_sspi_credential_handle.begin(), k_sspi_credential_handle.end());
                    if (it != request.end())
                    {
                        credential_offset = static_cast<size_t>(std::distance(request.begin(), it));
                    }
                }

                win_emu.log.print(color::gray,
                                  "SSPI_RPC procedure_id=6 body_length=" + std::to_string(c.send_buffer_length) +
                                      " captured_length=" + std::to_string(request.size()) + " credential_handle_round_tripped=" +
                                      (credential_offset ? "yes" : "no") + " credential_handle_offset=" +
                                      (credential_offset ? std::to_string(*credential_offset) : std::string{"unavailable"}) + "\n");

                constexpr size_t dump_chunk_size = 64;
                for (size_t offset = 0; offset < request.size(); offset += dump_chunk_size)
                {
                    const auto chunk_length = std::min(dump_chunk_size, request.size() - offset);
                    win_emu.log.print(color::gray, "SSPI_RPC procedure_6_body offset=" + std::to_string(offset) +
                                                       " data=" + sspi_hex_dump(request.data() + offset, chunk_length) + "\n");
                }

                return STATUS_NOT_SUPPORTED;
            }

            static NTSTATUS handle_connect_rpc(windows_emulator& win_emu, const lpc_request_context& c,
                                               utils::aligned_binary_writer& writer)
            {
                if (c.send_buffer_length != 12)
                {
                    win_emu.log.print(color::gray,
                                      "SSPI_RPC connect_rejected request_length=" + std::to_string(c.send_buffer_length) + "\n");
                    return STATUS_INVALID_PARAMETER;
                }

                const auto client_name_referent = win_emu.emu().read_memory<uint64_t>(c.send_buffer);
                const auto mode = win_emu.emu().read_memory<uint32_t>(c.send_buffer + 8);
                if (client_name_referent != 0 || mode != 2)
                {
                    win_emu.log.print(color::gray, "SSPI_RPC connect_rejected referent=" + std::to_string(client_name_referent) +
                                                       " mode=" + std::to_string(mode) + "\n");
                    return STATUS_INVALID_PARAMETER;
                }

                const auto reply_start = writer.position();
                writer.write<int32_t>(0);
                writer.write<int32_t>(1);
                writer.write<uint32_t>(0);
                writer.write(k_sspi_context_uuid.data(), k_sspi_context_uuid.size(), 1);
                writer.align_to(sizeof(uint32_t));
                writer.write<int32_t>(0);
                const auto reply_body_size = writer.position() - reply_start;

                win_emu.log.print(
                    color::gray,
                    "SSPI_RPC connect accepted input_length=12 referent=0 mode=2 reply_body_size=" + std::to_string(reply_body_size) +
                        " reply_body=" + sspi_hex_dump(k_sspi_connect_reply_body.data(), k_sspi_connect_reply_body.size()) + "\n");
                return STATUS_SUCCESS;
            }

            bool post_connect_operation_captured_{};
            uint64_t diagnostic_strings_{};
        };
    }

    std::unique_ptr<port> create_sspi_rpc_port()
    {
        return std::make_unique<sspi_rpc_port>();
    }

} // namespace sogen
