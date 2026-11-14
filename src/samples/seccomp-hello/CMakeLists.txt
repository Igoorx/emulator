find_program(SECCOMP_MINGW_CC
  NAMES aarch64-w64-mingw32-gcc aarch64-w64-mingw32-clang
  HINTS "$ENV{HOME}/mingw/bin"
  REQUIRED
)
function(add_seccomp_sample target source output_variable)
  set(sample "${CMAKE_CURRENT_BINARY_DIR}/${target}.exe")
  add_custom_command(OUTPUT "${sample}"
    COMMAND "${SECCOMP_MINGW_CC}" -std=c11 -O2 -Wall -Wextra -Werror -nostdlib
            -Wl,--entry,mainCRTStartup -Wl,--subsystem,console
            "${CMAKE_CURRENT_SOURCE_DIR}/${source}" -o "${sample}" -lkernel32
    DEPENDS "${source}" "${SECCOMP_MINGW_CC}"
    VERBATIM
  )
  add_custom_target(${target} DEPENDS "${sample}")
  set(${output_variable} "${sample}" PARENT_SCOPE)
endfunction()

add_seccomp_sample(seccomp-hello hello.c SECCOMP_SAMPLE)
add_seccomp_sample(seccomp-illegal-instruction illegal_instruction.c SECCOMP_ILLEGAL_INSTRUCTION_SAMPLE)
add_seccomp_sample(seccomp-single-step single_step.c SECCOMP_SINGLE_STEP_SAMPLE)
set(SECCOMP_SAMPLE "${SECCOMP_SAMPLE}" PARENT_SCOPE)
set(SECCOMP_ILLEGAL_INSTRUCTION_SAMPLE "${SECCOMP_ILLEGAL_INSTRUCTION_SAMPLE}" PARENT_SCOPE)
set(SECCOMP_SINGLE_STEP_SAMPLE "${SECCOMP_SINGLE_STEP_SAMPLE}" PARENT_SCOPE)
