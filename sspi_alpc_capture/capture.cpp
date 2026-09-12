#include "capture.hpp"

#include <security.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <vector>

namespace capture
{
    namespace
    {

        constexpr size_t kMaxCapture = 1024u * 1024u;
        constexpr wchar_t kTargetPort[] = L"\\RPC Control\\lsasspirpc";

        thread_local bool g_insideHook = false;

        struct HookGuard
        {
            HookGuard() noexcept
            {
                g_insideHook = true;
            }

            ~HookGuard()
            {
                g_insideHook = false;
            }
        };

        struct Snapshot
        {
            bool present = false;
            bool header_ok = false;
            bool raw_ok = false;
            bool payload_ok = false;
            std::string error;
            PORT_MESSAGE header{};
            std::vector<uint8_t> raw;
            std::vector<uint8_t> payload;
        };

        struct Transaction
        {
            uint64_t seq = 0;
            DWORD threadId = 0;
            uintptr_t port = 0;
            ULONG flags = 0;
            NTSTATUS status = 0;
            bool beforeLengthReadable = false;
            bool afterLengthReadable = false;
            SIZE_T lengthBefore = 0;
            SIZE_T lengthAfter = 0;
            Snapshot send;
            Snapshot receive;
        };

        struct ConnectRecord
        {
            bool available = false;
            DWORD threadId = 0;
            std::wstring name;
            ULONG flags = 0;
            NTSTATUS status = 0;
            uintptr_t handle = 0;
            bool beforeLengthReadable = false;
            bool afterLengthReadable = false;
            SIZE_T lengthBefore = 0;
            SIZE_T lengthAfter = 0;
            bool beforeOk = false;
            bool afterOk = false;
            std::string beforeError;
            std::string afterError;
            std::vector<uint8_t> before;
            std::vector<uint8_t> after;
        };

        std::atomic<uint64_t> g_nextSequence{0};
        std::atomic<uint64_t> g_captureFailures{0};
        std::mutex g_recordsMutex;
        std::vector<Transaction> g_transactions;
        ConnectRecord g_connect;

        // Isolated from C++ object lifetime management because MSVC does not permit
        // __try in a function that requires C++ unwinding.
        bool SehCopy(void* destination, const void* source, size_t size) noexcept
        {
            __try
            {
                std::memcpy(destination, source, size);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        template <typename T>
        bool SafeRead(const T* source, T& value) noexcept
        {
            return source && SehCopy(&value, source, sizeof(T));
        }

        bool SafeBytes(const void* source, size_t size, std::vector<uint8_t>& out, std::string& error)
        {
            if (!source)
            {
                error = "null pointer";
                return false;
            }
            if (size > kMaxCapture)
            {
                error = "requested copy exceeds 1 MiB limit";
                return false;
            }
            try
            {
                out.resize(size);
            }
            catch (...)
            {
                error = "memory allocation failed";
                return false;
            }
            if (size && !SehCopy(out.data(), source, size))
            {
                out.clear();
                error = "memory access fault while copying";
                return false;
            }
            return true;
        }

        Snapshot CaptureMessage(PPORT_MESSAGE message, std::optional<SIZE_T> receiveCapacity = std::nullopt)
        {
            Snapshot snap;
            snap.present = message != nullptr;
            if (!message)
            {
                return snap;
            }
            if (!SafeRead(message, snap.header))
            {
                snap.error = "PORT_MESSAGE header is unreadable";
                return snap;
            }
            snap.header_ok = true;
            const size_t total = snap.header.u1.s1.TotalLength;
            const size_t data = snap.header.u1.s1.DataLength;
            if (total < sizeof(PORT_MESSAGE))
            {
                snap.error = "TotalLength is smaller than PORT_MESSAGE";
                return snap;
            }
            if (total > kMaxCapture)
            {
                snap.error = "TotalLength exceeds 1 MiB limit";
                return snap;
            }
            if (receiveCapacity && total > *receiveCapacity)
            {
                snap.error = "TotalLength exceeds original receive capacity";
                return snap;
            }
            std::string rawError;
            snap.raw_ok = SafeBytes(message, total, snap.raw, rawError);
            if (!snap.raw_ok)
            {
                snap.error = rawError;
                return snap;
            }
            if (data > total - sizeof(PORT_MESSAGE))
            {
                snap.error = "DataLength extends past TotalLength";
                return snap;
            }
            std::string payloadError;
            snap.payload_ok = SafeBytes(reinterpret_cast<const uint8_t*>(message) + sizeof(PORT_MESSAGE), data, snap.payload, payloadError);
            if (!snap.payload_ok)
            {
                snap.error = payloadError;
            }
            return snap;
        }

        bool SafeReadUnicodeName(POBJECT_ATTRIBUTES attributes, std::wstring& out)
        {
            OBJECT_ATTRIBUTES oa{};
            if (!SafeRead(attributes, oa) || !oa.ObjectName)
            {
                return false;
            }
            UNICODE_STRING us{};
            if (!SafeRead(oa.ObjectName, us) || !us.Buffer || (us.Length % sizeof(wchar_t)) != 0 || us.Length > 64u * 1024u)
            {
                return false;
            }
            try
            {
                out.resize(us.Length / sizeof(wchar_t));
            }
            catch (...)
            {
                return false;
            }
            return us.Length == 0 || SehCopy(out.data(), us.Buffer, us.Length);
        }

        bool IsTargetName(const std::wstring& name) noexcept
        {
            return CompareStringOrdinal(name.data(), static_cast<int>(name.size()), kTargetPort, -1, TRUE) == CSTR_EQUAL;
        }

        std::string NarrowUtf8(const std::wstring& text)
        {
            if (text.empty())
            {
                return {};
            }
            const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0,
                                                  nullptr, nullptr);
            if (bytes <= 0)
            {
                return "<unicode-conversion-failed>";
            }
            std::string out(static_cast<size_t>(bytes), '\0');
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), bytes, nullptr,
                                nullptr);
            return out;
        }

        std::string HexPointer(uintptr_t value)
        {
            std::ostringstream os;
            os << "0x" << std::hex << value;
            return os.str();
        }

        bool WriteBinary(const std::filesystem::path& path, const std::vector<uint8_t>& bytes, std::string& error)
        {
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            if (!file)
            {
                error = "cannot create " + path.string();
                return false;
            }
            if (!bytes.empty())
            {
                file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }
            if (!file)
            {
                error = "write failed for " + path.string();
                return false;
            }
            return true;
        }

        std::string FileName(uint64_t seq, const char* suffix)
        {
            std::ostringstream os;
            os << std::setfill('0') << std::setw(4) << seq << suffix;
            return os.str();
        }

        void WriteSnapshotJson(std::ostream& os, const Snapshot& snap, const std::string& rawName, const std::string& payloadName)
        {
            if (!snap.present)
            {
                os << "null";
                return;
            }
            os << '{' << "\"header_readable\":" << (snap.header_ok ? "true" : "false")
               << ",\"raw_captured\":" << (snap.raw_ok ? "true" : "false")
               << ",\"payload_captured\":" << (snap.payload_ok ? "true" : "false");
            if (snap.header_ok)
            {
                os << ",\"data_length\":" << snap.header.u1.s1.DataLength << ",\"total_length\":" << snap.header.u1.s1.TotalLength
                   << ",\"type\":" << snap.header.u2.s2.Type << ",\"data_info_offset\":" << snap.header.u2.s2.DataInfoOffset
                   << ",\"client_pid\":\"" << HexPointer(reinterpret_cast<uintptr_t>(snap.header.ClientId.UniqueProcess)) << "\""
                   << ",\"client_tid\":\"" << HexPointer(reinterpret_cast<uintptr_t>(snap.header.ClientId.UniqueThread)) << "\""
                   << ",\"message_id\":" << snap.header.MessageId << ",\"client_view_size_or_callback_id\":\""
                   << HexPointer(static_cast<uintptr_t>(snap.header.ClientViewSize)) << "\"";
            }
            if (snap.raw_ok)
            {
                os << ",\"raw_file\":\"" << rawName << "\"";
            }
            if (snap.payload_ok)
            {
                os << ",\"payload_file\":\"" << payloadName << "\"";
            }
            if (!snap.error.empty())
            {
                os << ",\"error\":\"" << JsonEscape(snap.error) << "\"";
            }
            os << '}';
        }

    } // namespace

    NtAlpcConnectPortExFn RealNtAlpcConnectPortEx = nullptr;
    NtAlpcSendWaitReceivePortFn RealNtAlpcSendWaitReceivePort = nullptr;
    std::atomic<uintptr_t> SspiPortHandle{0};

    NTSTATUS NTAPI HookNtAlpcConnectPortEx(PHANDLE PortHandle, POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
                                           POBJECT_ATTRIBUTES ClientPortObjectAttributes, PNativeAlpcPortAttributes PortAttributes,
                                           ULONG Flags, PSECURITY_DESCRIPTOR ServerSecurityRequirements, PPORT_MESSAGE ConnectionMessage,
                                           PSIZE_T BufferLength, PNativeAlpcMessageAttributes OutMessageAttributes,
                                           PNativeAlpcMessageAttributes InMessageAttributes, PLARGE_INTEGER Timeout)
    {
        if (!RealNtAlpcConnectPortEx)
        {
            return static_cast<NTSTATUS>(0xC0000002L);
        }
        if (g_insideHook)
        {
            return RealNtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes, PortAttributes, Flags,
                                           ServerSecurityRequirements, ConnectionMessage, BufferLength, OutMessageAttributes,
                                           InMessageAttributes, Timeout);
        }
        HookGuard guard;

        std::wstring name;
        const bool nameReadable = SafeReadUnicodeName(ConnectionPortObjectAttributes, name);
        const bool target = nameReadable && IsTargetName(name);
        const std::string displayName = nameReadable ? NarrowUtf8(name) : "<unreadable name>";
        std::printf("[ALPC] connect attempt: %s\n", displayName.c_str());

        ConnectRecord local;
        if (target)
        {
            local.available = true;
            local.threadId = GetCurrentThreadId();
            local.name = name;
            local.flags = Flags;
            local.beforeLengthReadable = SafeRead(BufferLength, local.lengthBefore);
            if (ConnectionMessage && local.beforeLengthReadable && local.lengthBefore <= kMaxCapture)
            {
                local.beforeOk = SafeBytes(ConnectionMessage, local.lengthBefore, local.before, local.beforeError);
            }
            else if (ConnectionMessage)
            {
                local.beforeError = local.beforeLengthReadable ? "connection BufferLength before exceeds 1 MiB"
                                                               : "connection BufferLength before is unreadable";
            }
        }

        const NTSTATUS status = RealNtAlpcConnectPortEx(PortHandle, ConnectionPortObjectAttributes, ClientPortObjectAttributes,
                                                        PortAttributes, Flags, ServerSecurityRequirements, ConnectionMessage, BufferLength,
                                                        OutMessageAttributes, InMessageAttributes, Timeout);

        if (target)
        {
            local.status = status;
            HANDLE handle = nullptr;
            if (status >= 0 && SafeRead(PortHandle, handle))
            {
                local.handle = reinterpret_cast<uintptr_t>(handle);
                SspiPortHandle.store(local.handle, std::memory_order_release);
            }
            local.afterLengthReadable = SafeRead(BufferLength, local.lengthAfter);
            if (ConnectionMessage && local.afterLengthReadable && local.lengthAfter <= kMaxCapture &&
                (!local.beforeLengthReadable || local.lengthAfter <= local.lengthBefore))
            {
                local.afterOk = SafeBytes(ConnectionMessage, local.lengthAfter, local.after, local.afterError);
            }
            else if (ConnectionMessage)
            {
                local.afterError = !local.afterLengthReadable
                                       ? "connection BufferLength after is unreadable"
                                       : (local.lengthAfter > kMaxCapture ? "connection BufferLength after exceeds 1 MiB"
                                                                          : "connection BufferLength after exceeds original capacity");
            }
            try
            {
                std::lock_guard lock(g_recordsMutex);
                g_connect = std::move(local);
            }
            catch (...)
            {
                g_captureFailures.fetch_add(1, std::memory_order_relaxed);
            }
            if (status >= 0)
            {
                std::printf("[SSPI] connected \\RPC Control\\lsasspirpc\n"
                            "[SSPI] handle = %p\n[SSPI] status = 0x%08lX\n",
                            reinterpret_cast<void*>(SspiPortHandle.load()), static_cast<unsigned long>(status));
            }
            else
            {
                std::printf("[SSPI] connection to \\RPC Control\\lsasspirpc failed\n"
                            "[SSPI] status = 0x%08lX\n",
                            static_cast<unsigned long>(status));
            }
        }
        return status;
    }

    NTSTATUS NTAPI HookNtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, PPORT_MESSAGE SendMessage,
                                                 PNativeAlpcMessageAttributes SendMessageAttributes, PPORT_MESSAGE ReceiveMessage,
                                                 PSIZE_T BufferLength, PNativeAlpcMessageAttributes ReceiveMessageAttributes,
                                                 PLARGE_INTEGER Timeout)
    {
        if (!RealNtAlpcSendWaitReceivePort)
        {
            return static_cast<NTSTATUS>(0xC0000002L);
        }
        const uintptr_t target = SspiPortHandle.load(std::memory_order_acquire);
        if (g_insideHook || target == 0 || reinterpret_cast<uintptr_t>(PortHandle) != target)
        {
            return RealNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength,
                                                 ReceiveMessageAttributes, Timeout);
        }
        HookGuard guard;

        Transaction tx;
        tx.seq = g_nextSequence.fetch_add(1, std::memory_order_relaxed) + 1;
        tx.threadId = GetCurrentThreadId();
        tx.port = reinterpret_cast<uintptr_t>(PortHandle);
        tx.flags = Flags;
        try
        {
            tx.send = CaptureMessage(SendMessage);
        }
        catch (...)
        {
            tx.send.present = SendMessage != nullptr;
            tx.send.error = "C++ exception while capturing send message";
        }
        tx.beforeLengthReadable = SafeRead(BufferLength, tx.lengthBefore);

        tx.status = RealNtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength,
                                                  ReceiveMessageAttributes, Timeout);
        const NTSTATUS returnStatus = tx.status;

        tx.afterLengthReadable = SafeRead(BufferLength, tx.lengthAfter);
        try
        {
            tx.receive = tx.beforeLengthReadable ? CaptureMessage(ReceiveMessage, tx.lengthBefore) : CaptureMessage(ReceiveMessage);
        }
        catch (...)
        {
            tx.receive.present = ReceiveMessage != nullptr;
            tx.receive.error = "C++ exception while capturing receive message";
        }

        const size_t sendSize = tx.send.raw_ok ? tx.send.raw.size() : 0;
        const size_t recvSize = tx.receive.raw_ok ? tx.receive.raw.size() : 0;
        std::printf("[RPC #%llu] send = %zu bytes  recv = %zu bytes  status = 0x%08lX\n", static_cast<unsigned long long>(tx.seq), sendSize,
                    recvSize, static_cast<unsigned long>(tx.status));
        try
        {
            std::lock_guard lock(g_recordsMutex);
            g_transactions.push_back(std::move(tx));
        }
        catch (...)
        {
            g_captureFailures.fetch_add(1, std::memory_order_relaxed);
        }
        return returnStatus;
    }

    bool PrepareOutputDirectory(const std::filesystem::path& directory, std::string& error)
    {
        std::error_code ec;
        if (std::filesystem::exists(directory, ec))
        {
            if (ec)
            {
                error = "cannot inspect output directory: " + ec.message();
                return false;
            }
            if (!std::filesystem::is_directory(directory, ec))
            {
                error = directory.string() + " exists but is not a directory";
                return false;
            }
            if (std::filesystem::directory_iterator(directory, ec) != std::filesystem::directory_iterator())
            {
                error = directory.string() + " is not empty; move or remove the previous capture first";
                return false;
            }
            if (ec)
            {
                error = "cannot enumerate output directory: " + ec.message();
                return false;
            }
            return true;
        }
        if (!std::filesystem::create_directories(directory, ec) || ec)
        {
            error = "cannot create output directory: " + ec.message();
            return false;
        }
        return true;
    }

    bool Flush(const std::filesystem::path& directory, std::string& error)
    {
        std::vector<Transaction> transactions;
        ConnectRecord connect;
        {
            std::lock_guard lock(g_recordsMutex);
            transactions = g_transactions;
            connect = g_connect;
        }
        std::sort(transactions.begin(), transactions.end(), [](const Transaction& a, const Transaction& b) { return a.seq < b.seq; });

        if (connect.available)
        {
            if (connect.beforeOk && !WriteBinary(directory / "connect_before.bin", connect.before, error))
            {
                return false;
            }
            if (connect.afterOk && !WriteBinary(directory / "connect_after.bin", connect.after, error))
            {
                return false;
            }
            std::ofstream cj(directory / "connect.json", std::ios::trunc);
            if (!cj)
            {
                error = "cannot create connect.json";
                return false;
            }
            cj << "{\n  \"thread_id\": " << connect.threadId << ",\n  \"port_name\": \"" << JsonEscape(NarrowUtf8(connect.name)) << "\""
               << ",\n  \"flags\": \"" << HexPointer(connect.flags) << "\""
               << ",\n  \"status\": \"" << HexStatus(connect.status) << "\""
               << ",\n  \"port_handle\": \"" << HexPointer(connect.handle) << "\""
               << ",\n  \"buffer_length_before_readable\": " << (connect.beforeLengthReadable ? "true" : "false")
               << ",\n  \"buffer_length_before\": " << connect.lengthBefore
               << ",\n  \"buffer_length_after_readable\": " << (connect.afterLengthReadable ? "true" : "false")
               << ",\n  \"buffer_length_after\": " << connect.lengthAfter
               << ",\n  \"before_file\": " << (connect.beforeOk ? "\"connect_before.bin\"" : "null")
               << ",\n  \"after_file\": " << (connect.afterOk ? "\"connect_after.bin\"" : "null") << ",\n  \"before_error\": \""
               << JsonEscape(connect.beforeError) << "\""
               << ",\n  \"after_error\": \"" << JsonEscape(connect.afterError) << "\"\n}\n";
            if (!cj)
            {
                error = "write failed for connect.json";
                return false;
            }
        }

        std::ofstream jsonl(directory / "capture.jsonl", std::ios::trunc);
        if (!jsonl)
        {
            error = "cannot create capture.jsonl";
            return false;
        }
        for (const auto& tx : transactions)
        {
            const std::string sendRaw = FileName(tx.seq, "_send.bin");
            const std::string sendPayload = FileName(tx.seq, "_send_payload.bin");
            const std::string recvRaw = FileName(tx.seq, "_recv.bin");
            const std::string recvPayload = FileName(tx.seq, "_recv_payload.bin");
            if (tx.send.raw_ok && !WriteBinary(directory / sendRaw, tx.send.raw, error))
            {
                return false;
            }
            if (tx.send.payload_ok && !WriteBinary(directory / sendPayload, tx.send.payload, error))
            {
                return false;
            }
            if (tx.receive.raw_ok && !WriteBinary(directory / recvRaw, tx.receive.raw, error))
            {
                return false;
            }
            if (tx.receive.payload_ok && !WriteBinary(directory / recvPayload, tx.receive.payload, error))
            {
                return false;
            }

            jsonl << "{\"seq\":" << tx.seq << ",\"thread_id\":" << tx.threadId << ",\"port_handle\":\"" << HexPointer(tx.port) << "\""
                  << ",\"flags\":\"" << HexPointer(tx.flags) << "\""
                  << ",\"status\":\"" << HexStatus(tx.status) << "\""
                  << ",\"buffer_length_before_readable\":" << (tx.beforeLengthReadable ? "true" : "false")
                  << ",\"buffer_length_before\":" << tx.lengthBefore
                  << ",\"buffer_length_after_readable\":" << (tx.afterLengthReadable ? "true" : "false")
                  << ",\"buffer_length_after\":" << tx.lengthAfter << ",\"send\":";
            WriteSnapshotJson(jsonl, tx.send, sendRaw, sendPayload);
            jsonl << ",\"receive\":";
            WriteSnapshotJson(jsonl, tx.receive, recvRaw, recvPayload);
            jsonl << "}\n";
        }
        if (!jsonl)
        {
            error = "write failed for capture.jsonl";
            return false;
        }
        if (g_captureFailures.load(std::memory_order_relaxed) != 0)
        {
            std::ostringstream os;
            os << g_captureFailures.load() << " capture record(s) could not be retained in memory";
            error = os.str();
            return false;
        }
        return true;
    }

    uint64_t TransactionCount() noexcept
    {
        return g_nextSequence.load(std::memory_order_relaxed);
    }

    std::string HexStatus(LONG status)
    {
        std::ostringstream os;
        os << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << static_cast<unsigned long>(status);
        return os.str();
    }

    std::string SecurityStatusName(LONG status)
    {
        switch (status)
        {
        case SEC_E_OK:
            return "SEC_E_OK";
        case SEC_I_CONTINUE_NEEDED:
            return "SEC_I_CONTINUE_NEEDED";
        case SEC_I_COMPLETE_NEEDED:
            return "SEC_I_COMPLETE_NEEDED";
        case SEC_I_COMPLETE_AND_CONTINUE:
            return "SEC_I_COMPLETE_AND_CONTINUE";
        case SEC_E_INCOMPLETE_MESSAGE:
            return "SEC_E_INCOMPLETE_MESSAGE";
        case SEC_E_SECPKG_NOT_FOUND:
            return "SEC_E_SECPKG_NOT_FOUND";
        case SEC_E_NO_CREDENTIALS:
            return "SEC_E_NO_CREDENTIALS";
        case SEC_E_INTERNAL_ERROR:
            return "SEC_E_INTERNAL_ERROR";
        case SEC_E_INVALID_HANDLE:
            return "SEC_E_INVALID_HANDLE";
        case SEC_E_UNSUPPORTED_FUNCTION:
            return "SEC_E_UNSUPPORTED_FUNCTION";
        default:
            return {};
        }
    }

    std::string JsonEscape(const std::string& value)
    {
        std::ostringstream os;
        for (const unsigned char c : value)
        {
            switch (c)
            {
            case '\\':
                os << "\\\\";
                break;
            case '"':
                os << "\\\"";
                break;
            case '\b':
                os << "\\b";
                break;
            case '\f':
                os << "\\f";
                break;
            case '\n':
                os << "\\n";
                break;
            case '\r':
                os << "\\r";
                break;
            case '\t':
                os << "\\t";
                break;
            default:
                if (c < 0x20)
                {
                    os << "\\u" << std::hex << std::setfill('0') << std::setw(4) << static_cast<unsigned>(c) << std::dec;
                }
                else
                {
                    os << static_cast<char>(c);
                }
            }
        }
        return os.str();
    }

} // namespace capture
