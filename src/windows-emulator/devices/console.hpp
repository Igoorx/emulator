#pragma once

#include "../io_device.hpp"

namespace sogen
{

    bool is_console_input_available();

    std::unique_ptr<io_device> create_console_device(const device_creation_context& context);

} // namespace sogen
