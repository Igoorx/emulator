#pragma once

#include <Windows.h>
#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>

namespace capture
{

    // The Windows SDK does not expose the ALPC declarations consistently.
    // PORT_MESSAGE has the native x64 layout; the attribute structures remain
    // opaque because this utility only forwards their pointers unchanged.
    struct PORT_MESSAGE
    {
        union
        {
            struct
            {
                USHORT DataLength;
                USHORT TotalLength;
            } s1;

            ULONG Length;
        } u1;

        union
        {
            struct
            {
                USHORT Type;
                USHORT DataInfoOffset;
            } s2;

            ULONG ZeroInit;
        } u2;

        union
        {
            CLIENT_ID ClientId;
            double DoNotUseThisField;
        };

        ULONG MessageId;

        union
        {
            SIZE_T ClientViewSize;
            ULONG CallbackId;
        };
    };

    using PPORT_MESSAGE = PORT_MESSAGE*;
    static_assert(sizeof(PORT_MESSAGE) == 40);

    struct NativeAlpcPortAttributes;
    struct NativeAlpcMessageAttributes;
    using PNativeAlpcPortAttributes = NativeAlpcPortAttributes*;
    using PNativeAlpcMessageAttributes = NativeAlpcMessageAttributes*;

    using NtAlpcConnectPortExFn = NTSTATUS(NTAPI*)(PHANDLE PortHandle, POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
                                                   POBJECT_ATTRIBUTES ClientPortObjectAttributes, PNativeAlpcPortAttributes PortAttributes,
                                                   ULONG Flags, PSECURITY_DESCRIPTOR ServerSecurityRequirements,
                                                   PPORT_MESSAGE ConnectionMessage, PSIZE_T BufferLength,
                                                   PNativeAlpcMessageAttributes OutMessageAttributes,
                                                   PNativeAlpcMessageAttributes InMessageAttributes, PLARGE_INTEGER Timeout);

    using NtAlpcSendWaitReceivePortFn = NTSTATUS(NTAPI*)(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessage,
                                                         PNativeAlpcMessageAttributes SendMessageAttributes, PPORT_MESSAGE ReceiveMessage,
                                                         PSIZE_T BufferLength, PNativeAlpcMessageAttributes ReceiveMessageAttributes,
                                                         PLARGE_INTEGER Timeout);

    extern NtAlpcConnectPortExFn RealNtAlpcConnectPortEx;
    extern NtAlpcSendWaitReceivePortFn RealNtAlpcSendWaitReceivePort;
    extern std::atomic<uintptr_t> SspiPortHandle;

    NTSTATUS NTAPI HookNtAlpcConnectPortEx(PHANDLE PortHandle, POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
                                           POBJECT_ATTRIBUTES ClientPortObjectAttributes, PNativeAlpcPortAttributes PortAttributes,
                                           ULONG Flags, PSECURITY_DESCRIPTOR ServerSecurityRequirements, PPORT_MESSAGE ConnectionMessage,
                                           PSIZE_T BufferLength, PNativeAlpcMessageAttributes OutMessageAttributes,
                                           PNativeAlpcMessageAttributes InMessageAttributes, PLARGE_INTEGER Timeout);

    NTSTATUS NTAPI HookNtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessage,
                                                 PNativeAlpcMessageAttributes SendMessageAttributes, PPORT_MESSAGE ReceiveMessage,
                                                 PSIZE_T BufferLength, PNativeAlpcMessageAttributes ReceiveMessageAttributes,
                                                 PLARGE_INTEGER Timeout);

    // The directory must not already contain files; this prevents stale dumps from
    // being confused with the current run.
    bool PrepareOutputDirectory(const std::filesystem::path& directory, std::string& error);
    bool Flush(const std::filesystem::path& directory, std::string& error);
    uint64_t TransactionCount() noexcept;

    std::string SecurityStatusName(LONG status);
    std::string HexStatus(LONG status);
    std::string JsonEscape(const std::string& value);

} // namespace capture
