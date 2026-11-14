# Seccomp backend

The seccomp backend executes ARM64 Windows code directly on ARM64 Linux and Android hosts.
It uses Sogen's Windows PE loader, process and thread initialization, TEB/PEB setup, and syscall dispatcher.
Select it with `--backend seccomp` or `EMULATOR_SECCOMP=1`.

Counter-only native timing is enabled by default. Shared-data MMIO reads remain intercepted and
refresh the Windows timestamps on each read. Explicit `--native-timing=all` selects a periodically
refreshed shared-data page instead. Native timing is incompatible with `--reproducible`.

## Execution and exceptions

Guest addresses are host addresses in a reserved `[64 KiB, 64 GiB)` window. Reservation fails if
host mappings overlap the window. A thread-local seccomp filter traps syscall instructions in this
window with `SIGSYS`. The backend decodes the Windows syscall number from the `SVC` immediate and
passes it to the shared syscall dispatcher, with PC pointing to the `SVC` instruction.

Guest entry uses `SIGUSR2` and signal return; `SIGUSR1` requests a scheduler stop from another host
thread. The backend owns these signals and its synchronous fault handlers while the emulator is alive.
Signal entry restores the host's X18 and TLS before calling C++. Guest GPRs, NZCV, SP, PC and FPSIMD
state are saved before returning to the host stack, where emulator callbacks execute.

`SIGILL` becomes an ARM64 undefined-instruction exception at the faulting PC. The Windows exception
dispatcher delivers `STATUS_ILLEGAL_INSTRUCTION` with the saved guest registers. This includes
`MRS CurrentEL` at EL0; a guest handler can advance its saved PC and resume execution.

`PSTATE.SS` uses Linux `PTRACE_SINGLESTEP` to execute one instruction. A child tracer saves the host
registers, FPSIMD state and TLS, installs the guest state, captures the result, and restores the host
state before detaching. Successful steps report a software-step exception at the next PC with SS
cleared. Instructions that raise another exception, including `SVC`, cancel the pending step.
Tracing failures produce an error, including host policies that disallow a same-UID child from tracing
the CPU thread.

## MMIO

Read-only MMIO regions have inaccessible host pages. Memory faults return execution to the host
stack, where the backend decodes the load, calls the region-relative read callback, updates the guest
registers, and advances PC. Supported forms are:

- Integer and SIMD loads with unsigned, unscaled, register, pre-indexed or post-indexed offsets.
- Scalar `LDAR`, `LDAPR` and `LDAPUR` loads.
- Single-vector `LD1` with a `#16` post-increment and `.16B`, `.8H`, `.4S` or `.2D` arrangement.
- Byte-lane-zero `LD2` and `LD4` with `#2` and `#4` post-increments.

Indexed loads write back the base register, including SP, after a successful read. Byte-lane loads
preserve the other vector bytes. Emulated loads complete a pending software step.
Unsupported accesses raise an error, including stores, paired or exclusive loads, and overlapping
integer destination/base writeback.

## Host requirements and limits

The backend supports one emulator instance per process, one vCPU on its original host thread, and
4 KiB host pages. The seccomp filter and no-new-privileges setting remain active on that thread after
the emulator is destroyed. Guest code shares the host address space; this backend does not isolate
untrusted programs from the host.

Snapshots, counter interception, instruction-count execution budgets, execution hooks, recoverable
memory faults, and enabled hardware debug registers are unsupported and raise an error. Disabled debug
registers read as zero and accept zero. Thread stacks are committed in full because stack growth
cannot recover from memory faults. Memory read/write and basic-block observation hooks are accepted
without producing callbacks. Unsupported guest signals stop execution with PC and signal diagnostics.

## Build and run

A MinGW ARM64 Windows C compiler is required for the samples. CMake searches `~/mingw/bin` and PATH;
set `SECCOMP_MINGW_CC` to select another compiler. On Termux, add `-DSOGEN_ENABLE_AAUDIO=OFF` when configuring.
The Windows ARM64 emulation root must contain `filesys/c/windows/system32/apisetschema.dll` and registry hives.

```sh
export EMULATOR_ARM64_ROOT=/path/to/windows-arm64-root
cmake --preset release -DSOGEN_ENABLE_SECCOMP=ON
cmake --build --preset release --target analyzer seccomp-emulation-test -j2
ctest --test-dir build/release -R '^seccomp-emulation-test$' --output-on-failure
build/release/artifacts/analyzer --backend seccomp --no-inst-precision \
  --emulation "$EMULATOR_ARM64_ROOT" \
  --mount "$PWD/build/release/src/samples/seccomp-hello/seccomp-hello.exe:C:\seccomp-hello.exe:ro" \
  -s 'C:\seccomp-hello.exe'
```

The `seccomp-hello` sample calls `GetStdHandle`, `WriteFile` and `ExitProcess` through the Windows DLLs,
which route console output through `NtWriteFile`. It links without the C runtime and prints `Hello World`.
The regression target checks the console output and exit status, illegal-instruction delivery, hardware
single-stepping, MMIO load semantics, register preservation and base-register writeback. The
`seccomp-illegal-instruction` and `seccomp-single-step` samples exercise Windows guest exception handlers.

References: [Linux seccomp filter API](https://docs.kernel.org/userspace-api/seccomp_filter.html)
and [ASoftware iOS for Android](https://github.com/alpersamur3/asoft-ios-android).
