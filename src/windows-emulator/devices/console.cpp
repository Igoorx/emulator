#include "../std_include.hpp"
#include "console.hpp"

#include "../windows_emulator.hpp"
#include <iostream>

#ifndef _WIN32
#include <poll.h>
#include <unistd.h>
#endif

namespace sogen
{

    namespace
    {
        constexpr ULONG console_ioctl = 0x500016;

        enum class console_api : uint32_t
        {
            get_console_code_page = 0x01000000,
            get_console_mode = 0x01000001,
            set_console_mode = 0x01000002,
            get_console_input_event_count = 0x01000003,
            read_console_input = 0x01000004,
            write_console = 0x01000006,
            get_console_locale = 0x01000008,
            fill_console_output = 0x02000000,
            set_console_cursor_position = 0x0200000A,
            set_console_text_attribute = 0x0200000D,
            get_console_screen_buffer_info = 0x02000007,
        };

        constexpr uint32_t default_input_mode = 0x007F;
        constexpr uint32_t default_output_mode = 0x0003;

        bool is_host_input_available()
        {
            if (std::cin.rdbuf()->in_avail() > 0)
            {
                return true;
            }
#ifdef _WIN32
            return false;
#else
            pollfd descriptor{STDIN_FILENO, POLLIN, 0};
            return poll(&descriptor, 1, 0) > 0 && (descriptor.revents & (POLLIN | POLLHUP)) != 0;
#endif
        }

        enum class fill_console_output_type : uint32_t
        {
            ansi_character = 1,
            unicode_character = 2,
            attribute = 3,
        };

        struct console_coordinate
        {
            int16_t x;
            int16_t y;
        };

        static_assert(sizeof(console_coordinate) == 4);

        struct fill_console_output_request
        {
            console_coordinate coordinate;
            fill_console_output_type type;
            uint16_t value;
            uint16_t padding;
            uint32_t count;
        };

        static_assert(sizeof(fill_console_output_request) == 16);

        struct console_screen_buffer_info_response
        {
            int16_t size_x;
            int16_t size_y;
            int16_t cursor_x;
            int16_t cursor_y;
            int16_t window_left;
            int16_t window_top;
            uint16_t attributes;
            int16_t window_width;
            int16_t window_height;
            int16_t maximum_window_width;
            int16_t maximum_window_height;
            uint16_t popup_attributes;
            uint8_t fullscreen_supported;
            std::array<uint32_t, 16> color_table;
        };

        static_assert(sizeof(console_screen_buffer_info_response) == 92);

        struct console_ioctl_header
        {
            uint64_t target_handle;
            uint32_t input_count;
            uint32_t output_count;
            uint32_t message_buffer_size;
            uint32_t padding;
            uint64_t message;
            uint64_t data_size;
            uint64_t data;
        };

        static_assert(sizeof(console_ioctl_header) == 48);

        struct console_ioctl_input_header
        {
            console_ioctl_header header;
            uint32_t output_buffer_size;
            uint32_t padding;
            uint64_t output_buffer;
        };

        static_assert(sizeof(console_ioctl_input_header) == 64);

        struct read_console_input_request
        {
            uint32_t events_read;
            uint16_t flags;
            uint8_t unicode;
            uint8_t padding;
        };

        static_assert(sizeof(read_console_input_request) == 8);

        struct write_console_request
        {
            uint32_t characters_written;
            uint8_t unicode;
            std::array<uint8_t, 3> padding;
        };

        static_assert(sizeof(write_console_request) == 8);

        struct console_input_record
        {
            uint16_t event_type;
            uint16_t padding;
            int32_t key_down;
            uint16_t repeat_count;
            uint16_t virtual_key_code;
            uint16_t virtual_scan_code;
            char16_t unicode_character;
            uint32_t control_key_state;
        };

        static_assert(sizeof(console_input_record) == 20);

        struct console_message_header
        {
            uint32_t api_number;
            uint32_t data_size;
        };

    }

    bool is_console_input_available()
    {
        return is_host_input_available();
    }

    namespace
    {
        struct console_device final : io_device
        {
            void serialize_object(utils::buffer_serializer& buffer) const override
            {
                buffer.write(text_attributes_);
                buffer.write(cursor_position_);
                buffer.write(input_mode_);
                buffer.write(output_mode_);
            }

            void deserialize_object(utils::buffer_deserializer& buffer) override
            {
                buffer.read(text_attributes_);
                buffer.read(cursor_position_);
                buffer.read(input_mode_);
                buffer.read(output_mode_);
            }

            NTSTATUS io_control(windows_emulator& win_emu, const io_device_context& context) override
            {
                if (context.io_control_code != console_ioctl)
                {
                    return STATUS_NOT_SUPPORTED;
                }

                if (!context.input_buffer || context.input_buffer_length < sizeof(console_ioctl_header))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                console_ioctl_header header{};
                win_emu.emu().read_memory(context.input_buffer, &header, sizeof(header));
                if (header.target_handle != STDIN_HANDLE.h && header.target_handle != STDOUT_HANDLE.h &&
                    header.target_handle != CONSOLE_HANDLE.h && header.target_handle != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                if (header.message_buffer_size != sizeof(console_message_header) + header.data_size ||
                    header.data != header.message + sizeof(console_message_header) || !header.message || !header.data)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                console_message_header message{};
                win_emu.emu().read_memory(header.message, &message, sizeof(message));
                if (message.data_size != header.data_size)
                {
                    return STATUS_INVALID_PARAMETER;
                }
                switch (static_cast<console_api>(message.api_number))
                {
                case console_api::get_console_mode: {
                    if (message.data_size != sizeof(uint32_t))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    const auto mode = header.target_handle == STDIN_HANDLE.h ? input_mode_ : output_mode_;
                    win_emu.emu().write_memory(header.data, &mode, sizeof(mode));
                    return STATUS_SUCCESS;
                }

                case console_api::set_console_mode: {
                    if (message.data_size != sizeof(uint32_t))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    uint32_t mode{};
                    win_emu.emu().read_memory(header.data, &mode, sizeof(mode));
                    if (header.target_handle == STDIN_HANDLE.h)
                    {
                        input_mode_ = mode;
                    }
                    else
                    {
                        output_mode_ = mode;
                    }
                    return STATUS_SUCCESS;
                }

                case console_api::get_console_code_page: {
                    if (message.data_size != sizeof(uint64_t))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    constexpr uint64_t utf8_code_page = 65001;
                    win_emu.emu().write_memory(header.data, &utf8_code_page, sizeof(utf8_code_page));
                    return STATUS_SUCCESS;
                }
                case console_api::get_console_locale: {
                    if (header.input_count != 1 || header.output_count != 1 || message.data_size != sizeof(uint16_t))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    constexpr uint16_t english_united_states = 0x0409;
                    win_emu.emu().write_memory(header.data, &english_united_states, sizeof(english_united_states));
                    return STATUS_SUCCESS;
                }

                case console_api::get_console_input_event_count: {
                    if (header.target_handle != STDIN_HANDLE.h || header.input_count != 1 || header.output_count != 1 ||
                        message.data_size != sizeof(uint32_t))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    const uint32_t event_count = is_host_input_available() ? 1 : 0;
                    win_emu.emu().write_memory(header.data, &event_count, sizeof(event_count));
                    return STATUS_SUCCESS;
                }

                case console_api::read_console_input: {
                    if ((header.target_handle != STDIN_HANDLE.h && header.target_handle != 0) ||
                        context.input_buffer_length < sizeof(console_ioctl_input_header) || header.input_count != 1 ||
                        header.output_count != 2 || message.data_size != sizeof(read_console_input_request))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    console_ioctl_input_header input_header{};
                    win_emu.emu().read_memory(context.input_buffer, &input_header, sizeof(input_header));
                    if (!input_header.output_buffer || input_header.output_buffer_size < sizeof(console_input_record))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    const auto character = std::cin.get();
                    if (character == std::char_traits<char>::eof())
                    {
                        return STATUS_END_OF_FILE;
                    }

                    constexpr uint16_t key_event = 1;
                    constexpr uint32_t left_ctrl_pressed = 0x0008;

                    console_input_record record{};
                    record.event_type = key_event;
                    record.key_down = 1;
                    record.repeat_count = 1;
                    record.unicode_character = static_cast<char16_t>(static_cast<uint8_t>(character));

                    switch (character)
                    {
                    case '\n':
                    case '\r':
                        record.virtual_key_code = VK_RETURN;
                        record.virtual_scan_code = 0x1C;
                        record.unicode_character = u'\r';
                        break;
                    case '\t':
                        record.virtual_key_code = VK_TAB;
                        record.virtual_scan_code = 0x0F;
                        break;
                    case '\b':
                    case 0x7F:
                        record.virtual_key_code = VK_BACK;
                        record.virtual_scan_code = 0x0E;
                        record.unicode_character = u'\b';
                        break;
                    case 0x1B:
                        record.virtual_key_code = VK_ESCAPE;
                        record.virtual_scan_code = 0x01;
                        break;
                    default:
                        if (character > 0 && character <= 0x1A)
                        {
                            record.virtual_key_code = static_cast<uint16_t>('A' + character - 1);
                            record.control_key_state = left_ctrl_pressed;
                        }
                        else if (character >= 'a' && character <= 'z')
                        {
                            record.virtual_key_code = static_cast<uint16_t>('A' + character - 'a');
                        }
                        else
                        {
                            record.virtual_key_code = static_cast<uint16_t>(static_cast<uint8_t>(character));
                        }
                        break;
                    }

                    auto request = win_emu.emu().read_memory<read_console_input_request>(header.data);
                    request.events_read = 1;
                    win_emu.emu().write_memory(header.data, &request, sizeof(request));
                    win_emu.emu().write_memory(input_header.output_buffer, &record, sizeof(record));
                    return STATUS_SUCCESS;
                }
                case console_api::write_console: {
                    if ((header.target_handle != STDOUT_HANDLE.h && header.target_handle != 0) ||
                        context.input_buffer_length < sizeof(console_ioctl_input_header) || header.input_count != 2 ||
                        header.output_count != 1 || message.data_size != sizeof(write_console_request))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    console_ioctl_input_header input_header{};
                    win_emu.emu().read_memory(context.input_buffer, &input_header, sizeof(input_header));
                    auto request = win_emu.emu().read_memory<write_console_request>(header.data);
                    if (!input_header.output_buffer || (request.unicode && input_header.output_buffer_size % sizeof(char16_t) != 0))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    if (request.unicode)
                    {
                        std::u16string output(input_header.output_buffer_size / sizeof(char16_t), u'\0');
                        win_emu.emu().read_memory(input_header.output_buffer, output.data(), input_header.output_buffer_size);
                        win_emu.callbacks.on_stdout(u16_to_u8(output));
                        request.characters_written = static_cast<uint32_t>(output.size());
                    }
                    else
                    {
                        std::string output(input_header.output_buffer_size, '\0');
                        win_emu.emu().read_memory(input_header.output_buffer, output.data(), output.size());
                        win_emu.callbacks.on_stdout(output);
                        request.characters_written = static_cast<uint32_t>(output.size());
                    }

                    win_emu.emu().write_memory(header.data, &request, sizeof(request));
                    return STATUS_SUCCESS;
                }

                case console_api::fill_console_output: {
                    if (message.data_size != sizeof(fill_console_output_request))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    fill_console_output_request request{};
                    win_emu.emu().read_memory(header.data, &request, sizeof(request));
                    switch (request.type)
                    {
                    case fill_console_output_type::ansi_character:
                    case fill_console_output_type::unicode_character:
                    case fill_console_output_type::attribute:
                        // TODO
                        win_emu.emu().write_memory(header.data, &request, sizeof(request));
                        return STATUS_SUCCESS;
                    }

                    return STATUS_INVALID_PARAMETER;
                }

                case console_api::set_console_cursor_position:
                    if (message.data_size != sizeof(cursor_position_))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    win_emu.emu().read_memory(header.data, &cursor_position_, sizeof(cursor_position_));
                    return STATUS_SUCCESS;

                case console_api::set_console_text_attribute: {
                    if (message.data_size != sizeof(text_attributes_))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    win_emu.emu().read_memory(header.data, &text_attributes_, sizeof(text_attributes_));
                    return STATUS_SUCCESS;
                }

                case console_api::get_console_screen_buffer_info: {
                    if (message.data_size != sizeof(console_screen_buffer_info_response))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    console_screen_buffer_info_response response{};
                    response.size_x = 80;
                    response.size_y = 25;
                    response.cursor_x = cursor_position_.x;
                    response.cursor_y = cursor_position_.y;
                    response.window_width = response.size_x;
                    response.window_height = response.size_y;
                    response.maximum_window_width = response.size_x;
                    response.maximum_window_height = response.size_y;
                    response.attributes = text_attributes_;
                    response.popup_attributes = 0xF5;
                    response.color_table = {0x00000000, 0x00800000, 0x00008000, 0x00808000, 0x00000080, 0x00800080, 0x00008080, 0x00C0C0C0,
                                            0x00808080, 0x00FF0000, 0x0000FF00, 0x00FFFF00, 0x000000FF, 0x00FF00FF, 0x0000FFFF, 0x00FFFFFF};
                    win_emu.emu().write_memory(header.data, &response, sizeof(response));

                    return STATUS_SUCCESS;
                }
                default:
                    break;
                }

                return STATUS_INVALID_PARAMETER;
            }

          private:
            uint16_t text_attributes_{7};
            uint32_t input_mode_{default_input_mode};
            uint32_t output_mode_{default_output_mode};
            console_coordinate cursor_position_{};
        };
    }

    std::unique_ptr<io_device> create_console_device(const device_creation_context&)
    {
        return std::make_unique<console_device>();
    }

} // namespace sogen
