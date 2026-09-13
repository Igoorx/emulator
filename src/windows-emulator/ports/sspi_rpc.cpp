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
        constexpr uint64_t k_credential_lower = 9;
        constexpr uint64_t k_credential_upper = 0x10498;
        constexpr uint64_t k_context_lower = 9;
        constexpr uint64_t k_context_upper = 0x104a0;
        constexpr uint64_t k_expiry = 0x7fffff36d5969fff;
        constexpr uint32_t k_context_attributes = 0x0000c11c;
        constexpr uint32_t k_continue_needed = 0x00090312;
        constexpr uint32_t k_incomplete_message = 0x80090318;
        constexpr uint32_t k_invalid_handle = 0x80090301;
        constexpr std::array<uint8_t, 148> k_initial_token = {
            0x16, 0x03, 0x03, 0x00, 0x8f, 0x01, 0x00, 0x00, 0x8b, 0x03, 0x03, 0x6a, 0xa5, 0xdf, 0xde, 0x86, 0x69, 0x1d, 0x2f,
            0xe3, 0x4b, 0x8a, 0x26, 0x9c, 0x18, 0x11, 0x32, 0xb7, 0x22, 0x82, 0x0f, 0xfa, 0xf6, 0x85, 0x34, 0xb9, 0xb2, 0xa1,
            0xc5, 0xf7, 0xd7, 0x92, 0x91, 0x00, 0x00, 0x10, 0xc0, 0x2c, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2f, 0xc0, 0x24, 0xc0,
            0x23, 0xc0, 0x28, 0xc0, 0x27, 0x01, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x61,
            0x70, 0x69, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04,
            0x00, 0x18, 0x00, 0x17, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04, 0x08,
            0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02, 0x06, 0x01,
            0x06, 0x03, 0x00, 0x23, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00,
        };
        constexpr std::array<uint8_t, 126> k_final_handshake_token = {
            0x16, 0x03, 0x03, 0x00, 0x46, 0x10, 0x00, 0x00, 0x42, 0x41, 0x04, 0xaf, 0xc6, 0xbb, 0xf4, 0xab, 0xf2, 0x28, 0x04, 0xb7, 0x49,
            0x43, 0xf3, 0x20, 0x36, 0x1e, 0x15, 0xc1, 0xf7, 0x10, 0xff, 0x21, 0x7e, 0x40, 0xe7, 0x5c, 0xa8, 0x24, 0x54, 0xf8, 0xd5, 0xf1,
            0x47, 0x3b, 0xc3, 0xfe, 0x96, 0x4b, 0x16, 0x27, 0xab, 0x11, 0xed, 0x9f, 0xa2, 0xea, 0x92, 0xec, 0x49, 0x60, 0x39, 0xe6, 0x31,
            0x3e, 0x7e, 0xbd, 0x4a, 0x04, 0x94, 0x06, 0x79, 0x44, 0xc9, 0xa7, 0x83, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03,
            0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x60, 0x6d, 0xec, 0xa3, 0x31, 0xab, 0xa4, 0xda, 0x26, 0x95,
            0x53, 0x43, 0x7c, 0x4c, 0xf5, 0xdc, 0x4f, 0xb8, 0x45, 0x6d, 0x80, 0x97, 0xb6, 0x00, 0x1f, 0x1b, 0xdf, 0x3e, 0xf1, 0xb4, 0xca,
        };

        struct sspi_rpc_port : rpc_port
        {
            NTSTATUS handle_rpc(windows_emulator& win_emu, const uint32_t procedure_id, const lpc_request_context& c,
                                utils::aligned_binary_writer& writer, std::vector<alpc_reply_handle>&) override
            {
                if (this->bound_interface() != k_sspi_rpc_interface)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                switch (procedure_id)
                {
                case 0:
                    return handle_connect_rpc(win_emu, c, writer);
                case 3:
                    return handle_call_rpc(win_emu, c, writer);
                case 4:
                    return handle_acquire_credentials(win_emu, c, writer);
                case 5:
                    return handle_free_credentials(win_emu, c, writer);
                case 6:
                    return handle_process_security_context(win_emu, c, writer);
                case 7:
                    return handle_delete_security_context(win_emu, c, writer);
                default:
                    return STATUS_NOT_SUPPORTED;
                }
            }

          private:
            struct security_handle
            {
                uint64_t lower{};
                uint64_t upper{};

                bool operator==(const security_handle&) const = default;
            };

            struct decoded_buffer
            {
                uint32_t size{};
                uint32_t type{};
                uint64_t referent{};
                size_t payload_offset{};
            };

            struct context_request
            {
                security_handle credential{};
                security_handle context{};
                uint32_t requested_attributes{};
                uint32_t representation{};
                std::string target{};
                std::vector<decoded_buffer> buffers{};
                std::vector<uint8_t> bytes{};
            };

            struct credential_record
            {
                security_handle handle{k_credential_lower, k_credential_upper};
                bool live{};
            };

            struct context_record
            {
                security_handle handle{k_context_lower, k_context_upper};
                security_handle credential{};
                std::string target{};
                std::vector<uint8_t> pending_input{};
                uint32_t phase{};
                bool live{};
                bool finalized{};
            };

            template <typename T>
            static bool read_value(const std::span<const uint8_t> bytes, const size_t offset, T& value)
            {
                if (offset > bytes.size() || bytes.size() - offset < sizeof(value))
                {
                    return false;
                }

                std::memcpy(&value, bytes.data() + offset, sizeof(value));
                return true;
            }

            static size_t align_up(const size_t value, const size_t alignment)
            {
                return (value + alignment - 1) & ~(alignment - 1);
            }

            static bool has_port_context(const std::span<const uint8_t> request)
            {
                return request.size() >= k_sspi_context_handle.size() &&
                       std::memcmp(request.data(), k_sspi_context_handle.data(), k_sspi_context_handle.size()) == 0;
            }

            static std::optional<std::vector<uint8_t>> read_request(windows_emulator& win_emu, const lpc_request_context& c)
            {
                if (c.send_buffer == 0)
                {
                    return std::nullopt;
                }

                std::vector<uint8_t> request(c.send_buffer_length);
                if (!request.empty())
                {
                    win_emu.emu().read_memory(c.send_buffer, request.data(), request.size());
                }
                return request;
            }

            static bool matches_marshaled_handle(const security_handle value, const security_handle expected)
            {
                return value.upper == expected.upper && (value.lower == 0 || value.lower == expected.lower);
            }

            static bool finish_reply(utils::aligned_binary_writer& writer, const uint64_t start, const size_t expected_size)
            {
                const auto size = writer.offset() - start;
                if (size > expected_size)
                {
                    return false;
                }

                writer.pad(expected_size - static_cast<size_t>(size));
                return true;
            }

            static void write_callback_result(utils::aligned_binary_writer& writer)
            {
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
            }

            static bool valid_complete_tls_records(const std::span<const uint8_t> data)
            {
                size_t offset = 0;
                while (offset < data.size())
                {
                    if (data.size() - offset < 5 || data[offset + 1] != 3 || data[offset + 2] != 3)
                    {
                        return false;
                    }

                    const size_t record_size = 5 + (static_cast<size_t>(data[offset + 3]) << 8) + data[offset + 4];
                    if (record_size > data.size() - offset)
                    {
                        return false;
                    }
                    offset += record_size;
                }
                return true;
            }

            static bool decode_context_request(windows_emulator& win_emu, const lpc_request_context& c, context_request& result)
            {
                auto request = read_request(win_emu, c);
                if (!request || request->size() < 0x60 || !has_port_context(*request))
                {
                    return false;
                }

                result.bytes = std::move(*request);
                const std::span<const uint8_t> bytes{result.bytes};
                uint16_t target_length{};
                uint16_t target_maximum_length{};
                uint64_t target_referent{};
                uint64_t target_buffer_referent{};
                uint64_t target_maximum_count{};
                uint64_t target_offset{};
                uint64_t target_count{};
                if (!read_value(bytes, 0x30, target_referent) || !read_value(bytes, 0x38, target_length) ||
                    !read_value(bytes, 0x3a, target_maximum_length) || !read_value(bytes, 0x40, target_buffer_referent) ||
                    !read_value(bytes, 0x48, target_maximum_count) || !read_value(bytes, 0x50, target_offset) ||
                    !read_value(bytes, 0x58, target_count) || target_referent == 0 || target_buffer_referent == 0 ||
                    target_length % 2 != 0 || target_maximum_length % 2 != 0 || target_length > target_maximum_length ||
                    target_offset != 0 || target_maximum_count != target_maximum_length / 2 || target_count != target_length / 2 ||
                    target_count > (bytes.size() - 0x60) / sizeof(char16_t))
                {
                    return false;
                }

                result.target.reserve(static_cast<size_t>(target_count));
                for (size_t index = 0; index < target_count; ++index)
                {
                    uint16_t character{};
                    if (!read_value(bytes, 0x60 + index * sizeof(character), character) || character > 0x7f)
                    {
                        return false;
                    }
                    result.target.push_back(static_cast<char>(character));
                }

                const size_t arguments = align_up(0x60 + static_cast<size_t>(target_count) * sizeof(char16_t), 8);
                uint64_t input_ip_referent{};
                uint64_t arg_9_referent{};
                uint32_t arg_10_version{};
                uint32_t arg_10_buffer_count{};
                uint64_t arg_10_buffers_referent{};
                if (!read_value(bytes, arguments + 0x00, result.credential.lower) ||
                    !read_value(bytes, arguments + 0x08, result.credential.upper) ||
                    !read_value(bytes, arguments + 0x10, result.context.lower) ||
                    !read_value(bytes, arguments + 0x18, result.context.upper) ||
                    !read_value(bytes, arguments + 0x20, result.requested_attributes) ||
                    !read_value(bytes, arguments + 0x24, result.representation) ||
                    !read_value(bytes, arguments + 0x28, input_ip_referent) || !read_value(bytes, arguments + 0x30, arg_9_referent) ||
                    !read_value(bytes, arguments + 0x38, arg_10_version) || !read_value(bytes, arguments + 0x3c, arg_10_buffer_count) ||
                    !read_value(bytes, arguments + 0x40, arg_10_buffers_referent) || input_ip_referent != 0 || arg_9_referent != 0 ||
                    arg_10_version != 0)
                {
                    return false;
                }

                size_t offset = arguments + 0x48;
                uint64_t arg_10_deferred_count{};
                if (arg_10_buffers_referent != 0)
                {
                    if (!read_value(bytes, offset, arg_10_deferred_count) || arg_10_deferred_count != arg_10_buffer_count)
                    {
                        return false;
                    }
                    offset += sizeof(uint64_t);
                }
                else if (arg_10_buffer_count != 0)
                {
                    return false;
                }

                if (arg_10_deferred_count > (bytes.size() - offset) / 0x10)
                {
                    return false;
                }

                result.buffers.reserve(static_cast<size_t>(arg_10_deferred_count));
                for (size_t index = 0; index < arg_10_deferred_count; ++index)
                {
                    decoded_buffer buffer{};
                    const size_t buffer_offset = offset + index * 0x10;
                    if (!read_value(bytes, buffer_offset, buffer.size) || !read_value(bytes, buffer_offset + 4, buffer.type) ||
                        !read_value(bytes, buffer_offset + 8, buffer.referent))
                    {
                        return false;
                    }
                    result.buffers.push_back(buffer);
                }
                offset += static_cast<size_t>(arg_10_deferred_count) * 0x10;

                for (auto& buffer : result.buffers)
                {
                    if (buffer.referent == 0)
                    {
                        if (buffer.size != 0)
                        {
                            return false;
                        }
                        continue;
                    }

                    uint64_t payload_count{};
                    if (!read_value(bytes, offset, payload_count) || payload_count != buffer.size)
                    {
                        return false;
                    }
                    offset += sizeof(uint64_t);
                    if (payload_count > bytes.size() - offset)
                    {
                        return false;
                    }
                    buffer.payload_offset = offset;
                    offset = align_up(offset + static_cast<size_t>(payload_count), 8);
                }

                uint32_t arg_11_member_0{};
                uint32_t arg_11_member_1{};
                uint64_t arg_11_array_referent{};
                if (!read_value(bytes, offset, arg_11_member_0) || !read_value(bytes, offset + 4, arg_11_member_1) ||
                    !read_value(bytes, offset + 8, arg_11_array_referent) || arg_11_member_0 != 0)
                {
                    return false;
                }
                offset += 0x10;
                if (arg_11_array_referent != 0)
                {
                    uint64_t conformant_count{};
                    if (!read_value(bytes, offset, conformant_count) || conformant_count != arg_11_member_1 ||
                        conformant_count > (bytes.size() - offset - sizeof(uint64_t)) / 8)
                    {
                        return false;
                    }
                    offset += sizeof(uint64_t) + static_cast<size_t>(conformant_count) * 8;
                }
                else if (arg_11_member_1 != 0)
                {
                    return false;
                }

                return offset <= bytes.size() && bytes.size() - offset == 0x30;
            }

            static std::span<const uint8_t> buffer_payload(const context_request& request, const decoded_buffer& buffer)
            {
                return {request.bytes.data() + buffer.payload_offset, buffer.size};
            }

            NTSTATUS handle_call_rpc(windows_emulator& win_emu, const lpc_request_context& c, utils::aligned_binary_writer& writer)
            {
                auto request = read_request(win_emu, c);
                uint32_t declared_length{};
                uint64_t conformant_count{};
                uint32_t api{};
                uint64_t package_id{};
                uint64_t client_context{};
                uint64_t client_process{};
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64 || !request || request->size() != 0xf8 ||
                    !has_port_context(*request) || !read_value(*request, 0x14, declared_length) ||
                    !read_value(*request, 0x18, conformant_count) || !read_value(*request, 0x28, client_context) ||
                    !read_value(*request, 0x30, client_process) || !read_value(*request, 0x48, api) ||
                    !read_value(*request, 0x60, package_id) || declared_length != 0xd8 || conformant_count != 0xd8 || api != 4 ||
                    package_id >= 12 || writer.offset() != 0x18)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                constexpr std::u16string_view package_name = u"Microsoft Unified Security Protocol Provider";
                constexpr std::u16string_view package_comment = u"Schannel Security Package";
                constexpr std::u16string_view module_name = u"C:\\Windows\\system32\\schannel.DLL";
                if (this->package_strings_ == 0)
                {
                    this->package_strings_ = win_emu.memory.allocate_memory(0x1000, nt_memory_permission{memory_permission::read_write});
                    if (this->package_strings_ == 0)
                    {
                        return STATUS_NO_MEMORY;
                    }
                    win_emu.emu().write_memory(this->package_strings_, package_name.data(), package_name.size() * sizeof(char16_t));
                    win_emu.emu().write_memory(this->package_strings_ + 0x5a, package_comment.data(),
                                               package_comment.size() * sizeof(char16_t));
                    win_emu.emu().write_memory(this->package_strings_ + 0x8e, module_name.data(), module_name.size() * sizeof(char16_t));
                }

                const auto start = writer.offset();
                writer.write<int32_t>(0xd8);
                writer.write_ndr_pointer(true);
                writer.write_pointer_sized(0xd8);
                writer.write<uint16_t>(0xb0);
                writer.write<uint16_t>(0xd8);
                writer.write<uint32_t>(0);
                writer.write<uint64_t>(client_context);
                writer.write<uint64_t>(client_process);
                writer.write<uint64_t>(0);
                writer.write<uint64_t>(0);
                writer.write<uint32_t>(api);
                writer.align_to(8);
                writer.write<uint64_t>(0);
                writer.write<uint64_t>(package_id);
                writer.write<uint64_t>(0);
                writer.write<uint16_t>(0x58);
                writer.write<uint16_t>(0x5a);
                writer.align_to(8);
                writer.write<uint64_t>(this->package_strings_);
                writer.write<uint16_t>(0x32);
                writer.write<uint16_t>(0x34);
                writer.align_to(8);
                writer.write<uint64_t>(this->package_strings_ + 0x5a);
                writer.write<uint16_t>(0x40);
                writer.write<uint16_t>(0x42);
                writer.align_to(8);
                writer.write<uint64_t>(this->package_strings_ + 0x8e);
                writer.write<uint32_t>(1);
                writer.write<uint32_t>(0x004107b3);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(14);
                writer.write<uint32_t>(1);
                writer.write<uint32_t>(0x6000);
                writer.write<uint32_t>(14);
                constexpr std::array<uint32_t, 16> context_thunks = {
                    6, 89, 84, 82, 91, 94, 102, 34, 103, 104, 113, 107, 117, 0x00c10076, 0, 0,
                };
                for (const auto thunk : context_thunks)
                {
                    writer.write<uint32_t>(thunk);
                }
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
                if (!finish_reply(writer, start, 0x140))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                this->package_calls_ |= uint16_t{1} << package_id;
                return STATUS_SUCCESS;
            }

            NTSTATUS handle_acquire_credentials(windows_emulator& win_emu, const lpc_request_context& c,
                                                utils::aligned_binary_writer& writer)
            {
                auto request = read_request(win_emu, c);
                uint16_t package_length{};
                uint16_t package_maximum_length{};
                uint64_t package_referent{};
                uint64_t package_count{};
                uint32_t credential_use{};
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64 || !request || request->size() < 0xc4 ||
                    !has_port_context(*request) || !read_value(*request, 0x40, package_length) ||
                    !read_value(*request, 0x42, package_maximum_length) || !read_value(*request, 0x48, package_referent) ||
                    !read_value(*request, 0x60, package_count) || !read_value(*request, 0xc0, credential_use) || package_length != 0x58 ||
                    package_maximum_length != 0x5a || package_referent == 0 || package_count != 44 || credential_use != 2 ||
                    writer.offset() != 0x18 || this->package_calls_ == 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                constexpr std::u16string_view package_name = u"Microsoft Unified Security Protocol Provider";
                if (std::memcmp(request->data() + 0x68, package_name.data(), package_name.size() * sizeof(char16_t)) != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                this->credential_.live = true;
                const auto start = writer.offset();
                writer.write<uint64_t>(this->credential_.handle.lower);
                writer.write<uint64_t>(this->credential_.handle.upper);
                writer.write<uint64_t>(k_expiry);
                write_callback_result(writer);
                if (!finish_reply(writer, start, 0xa0))
                {
                    return STATUS_INVALID_PARAMETER;
                }
                return STATUS_SUCCESS;
            }

            static void write_context_reply(utils::aligned_binary_writer& writer, const uint32_t input_offset,
                                            const std::span<const uint8_t> token, const uint32_t input_extra_size,
                                            const uint32_t input_extra_type, const security_handle context, const uint32_t package_status,
                                            const uint64_t expiry, const size_t reply_size)
            {
                const auto start = writer.offset();
                writer.write<uint32_t>(input_offset);
                writer.align_to(8);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(1);
                writer.write_ndr_pointer(true);
                writer.write_pointer_sized(1);
                writer.write<uint32_t>(static_cast<uint32_t>(token.size()));
                writer.write<uint32_t>(2);
                writer.write_ndr_pointer(!token.empty());
                if (!token.empty())
                {
                    writer.write_pointer_sized(token.size());
                    writer.write(token.data(), token.size(), 1);
                    writer.align_to(8);
                }

                writer.write_ndr_pointer(input_extra_type != 0);
                writer.write<uint32_t>(0);
                writer.write<uint32_t>(input_extra_type != 0 ? 2 : 0);
                writer.write_ndr_pointer(input_extra_type != 0);
                if (input_extra_type != 0)
                {
                    writer.write_pointer_sized(2);
                    writer.write<uint32_t>(0);
                    writer.write<uint32_t>(0);
                    writer.write<uint32_t>(input_extra_size);
                    writer.write<uint32_t>(input_extra_type);
                    writer.write_ndr_pointer(false);
                    writer.write_ndr_pointer(false);
                }

                writer.write<uint64_t>(context.lower);
                writer.write<uint64_t>(context.upper);
                writer.write<uint32_t>(k_context_attributes);
                writer.align_to(8);
                writer.write<uint64_t>(expiry);
                writer.write<uint32_t>(package_status);
                writer.align_to(8);
                write_callback_result(writer);
                finish_reply(writer, start, reply_size);
            }

            NTSTATUS handle_process_security_context(windows_emulator& win_emu, const lpc_request_context& c,
                                                     utils::aligned_binary_writer& writer)
            {
                context_request request{};
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64 || writer.offset() != 0x18 ||
                    !decode_context_request(win_emu, c, request) || !this->credential_.live ||
                    !matches_marshaled_handle(request.credential, this->credential_.handle) || request.target != "api.github.com" ||
                    request.requested_attributes != k_context_attributes || request.representation != 0x10)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                if (!this->context_.live)
                {
                    if (request.context != security_handle{} || !request.buffers.empty())
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    this->context_ = {.handle = {k_context_lower, k_context_upper},
                                      .credential = this->credential_.handle,
                                      .target = request.target,
                                      .phase = 1,
                                      .live = true};
                    write_context_reply(writer, 0, k_initial_token, 0, 0, this->context_.handle, k_continue_needed, 0, 0x1e0);
                    return STATUS_SUCCESS;
                }

                if (!matches_marshaled_handle(request.context, this->context_.handle) || request.buffers.size() != 2 ||
                    request.buffers[1].size != 0 || request.buffers[1].type != 0 || request.buffers[1].referent != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                const auto input = buffer_payload(request, request.buffers[0]);

                switch (this->context_.phase)
                {
                case 1:
                    if (input.size() != 1024 || input.size() < 70 || input[0] != 0x16 || input[3] != 0 || input[4] != 0x41 ||
                        input[70] != 0x16)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    this->context_.pending_input.assign(input.begin() + 70, input.end());
                    this->context_.phase = 2;
                    write_context_reply(writer, 0, {}, 954, 5, this->context_.handle, k_continue_needed, k_expiry, 0x168);
                    return STATUS_SUCCESS;
                case 2:
                    if (!std::ranges::equal(input, this->context_.pending_input))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    this->context_.phase = 3;
                    write_context_reply(writer, 0x10, {}, 1786, 4, this->context_.handle, k_incomplete_message, 0, 0x168);
                    return STATUS_SUCCESS;
                case 3:
                    if (input.size() != 2740 || input.size() < this->context_.pending_input.size() ||
                        !std::ranges::equal(this->context_.pending_input, input.first(this->context_.pending_input.size())) ||
                        !valid_complete_tls_records(input))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    this->context_.pending_input.clear();
                    this->context_.phase = 4;
                    write_context_reply(writer, 0, {}, 0, 0, this->context_.handle, k_continue_needed, k_expiry, 0x140);
                    return STATUS_SUCCESS;
                case 4:
                    if (input.size() != 162 || !valid_complete_tls_records(input))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    this->context_.phase = 5;
                    write_context_reply(writer, 0, k_final_handshake_token, 0, 0, this->context_.handle, k_continue_needed, k_expiry,
                                        0x1c8);
                    return STATUS_SUCCESS;
                case 5:
                    if (input.size() != 51 || !valid_complete_tls_records(input))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    this->context_.phase = 6;
                    this->context_.finalized = true;
                    write_context_reply(writer, 0, {}, 0, 0, this->context_.handle, 0, k_expiry, 0x140);
                    return STATUS_SUCCESS;
                default:
                    return STATUS_INVALID_PARAMETER;
                }
            }

            NTSTATUS handle_delete_security_context(windows_emulator& win_emu, const lpc_request_context& c,
                                                    utils::aligned_binary_writer& writer)
            {
                auto request = read_request(win_emu, c);
                security_handle handle{};
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64 || !request || request->size() != 0x38 ||
                    !has_port_context(*request) || !read_value(*request, 0x28, handle.lower) || !read_value(*request, 0x30, handle.upper) ||
                    writer.offset() != 0x18)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                const uint32_t status =
                    this->context_.live && matches_marshaled_handle(handle, this->context_.handle) ? 0 : k_invalid_handle;
                if (status == 0)
                {
                    this->context_.live = false;
                }
                const auto start = writer.offset();
                writer.write<uint32_t>(status);
                write_callback_result(writer);
                if (!finish_reply(writer, start, 0x38))
                {
                    return STATUS_INVALID_PARAMETER;
                }
                return STATUS_SUCCESS;
            }

            NTSTATUS handle_free_credentials(windows_emulator& win_emu, const lpc_request_context& c, utils::aligned_binary_writer& writer)
            {
                auto request = read_request(win_emu, c);
                security_handle handle{};
                if (writer.pointer_size() != utils::aligned_binary_writer::pointer_size_64 || !request || request->size() != 0x38 ||
                    !has_port_context(*request) || !read_value(*request, 0x28, handle.lower) || !read_value(*request, 0x30, handle.upper) ||
                    writer.offset() != 0x18)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                const uint32_t status =
                    this->credential_.live && matches_marshaled_handle(handle, this->credential_.handle) ? 0 : k_invalid_handle;
                if (status == 0)
                {
                    this->credential_.live = false;
                }
                const auto start = writer.offset();
                writer.write<uint32_t>(status);
                write_callback_result(writer);
                if (!finish_reply(writer, start, 0x38))
                {
                    return STATUS_INVALID_PARAMETER;
                }
                return STATUS_SUCCESS;
            }

            NTSTATUS handle_connect_rpc(windows_emulator& win_emu, const lpc_request_context& c, utils::aligned_binary_writer& writer)
            {
                uint64_t client_name_referent{};
                uint32_t mode{};
                if (c.send_buffer_length != 12 || c.send_buffer == 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                client_name_referent = win_emu.emu().read_memory<uint64_t>(c.send_buffer);
                mode = win_emu.emu().read_memory<uint32_t>(c.send_buffer + 8);
                if (client_name_referent != 0 || mode != 2)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                writer.write<int32_t>(0);
                writer.write<int32_t>(1);
                writer.write<uint32_t>(0);
                writer.write(k_sspi_context_uuid.data(), k_sspi_context_uuid.size(), 1);
                writer.align_to(sizeof(uint32_t));
                writer.write<int32_t>(0);
                this->connected_ = true;
                return STATUS_SUCCESS;
            }

            bool connected_{};
            uint16_t package_calls_{};
            uint64_t package_strings_{};
            credential_record credential_{};
            context_record context_{};
        };
    }

    std::unique_ptr<port> create_sspi_rpc_port()
    {
        return std::make_unique<sspi_rpc_port>();
    }

} // namespace sogen
