#include "../std_include.hpp"
#include "sspi_context.hpp"

#include <chrono>
#include <ctime>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace sogen::sspi
{
    namespace
    {
        constexpr uint32_t serialized_packed_context = 1;
        constexpr uint32_t serialized_read_key = 2;
        constexpr uint32_t serialized_write_key = 3;
        constexpr uint32_t serialized_provider_name = 9;
        constexpr uint32_t serialized_remote_certificate = 0x15;
        constexpr uint32_t serialized_chain_index_property = 0xe697;
        constexpr uint32_t serialized_sha1_property = 3;
        constexpr uint32_t serialized_certificate_property = 0x20;
        constexpr uint32_t serialized_chain_context_property = 0x77;
        constexpr uint32_t serialized_chain_context_magic = 0x43435343;
        constexpr size_t serialized_chain_context_header_size = 0xa0;
        constexpr size_t serialized_chain_context_element_size = 0x38;
        constexpr size_t ssl3_wrapper_size = 80;
        constexpr size_t opaque_blob_size = 0x230;
        constexpr uint32_t opaque_blob_magic = 0x4d53534b;
        constexpr uint32_t opaque_algorithm = 0x00010002;
        constexpr uint32_t opaque_mode = 5;
        constexpr uint32_t opaque_flags = 0x80;
        constexpr size_t aes_128_key_size = 16;
        constexpr size_t aes_schedule_size = 0x150;
        constexpr uint32_t ssl3_magic = 0x73736c33;
        constexpr uint32_t tls_1_2 = 0x0303;
        constexpr uint32_t tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b;

        template <typename T>
        void write_value(std::span<uint8_t> bytes, const size_t offset, const T value)
        {
            std::memcpy(bytes.data() + offset, &value, sizeof(value));
        }

        uint8_t galois_multiply(uint8_t lhs, uint8_t rhs)
        {
            uint8_t result{};
            for (size_t bit = 0; bit < 8; ++bit)
            {
                if ((rhs & 1) != 0)
                {
                    result ^= lhs;
                }
                const bool high_bit = (lhs & 0x80) != 0;
                lhs = static_cast<uint8_t>(lhs << 1);
                if (high_bit)
                {
                    lhs ^= 0x1b;
                }
                rhs >>= 1;
            }
            return result;
        }

        uint8_t aes_sbox(const uint8_t value)
        {
            uint8_t inverse{};
            if (value != 0)
            {
                inverse = 1;
                uint8_t base = value;
                uint16_t exponent = 254;
                while (exponent != 0)
                {
                    if ((exponent & 1) != 0)
                    {
                        inverse = galois_multiply(inverse, base);
                    }
                    base = galois_multiply(base, base);
                    exponent >>= 1;
                }
            }

            const auto rotate_left = [](const uint8_t input, const uint8_t shift) {
                return static_cast<uint8_t>((input << shift) | (input >> (8 - shift)));
            };
            return static_cast<uint8_t>(inverse ^ rotate_left(inverse, 1) ^ rotate_left(inverse, 2) ^ rotate_left(inverse, 3) ^
                                        rotate_left(inverse, 4) ^ 0x63);
        }

        void write_inverse_mix_columns(std::array<uint8_t, aes_schedule_size>& schedule, const size_t destination_offset,
                                       const size_t source_offset)
        {
            const auto a0 = schedule[source_offset];
            const auto a1 = schedule[source_offset + 1];
            const auto a2 = schedule[source_offset + 2];
            const auto a3 = schedule[source_offset + 3];
            schedule[destination_offset] = static_cast<uint8_t>(galois_multiply(a0, 0x0e) ^ galois_multiply(a1, 0x0b) ^
                                                                galois_multiply(a2, 0x0d) ^ galois_multiply(a3, 0x09));
            schedule[destination_offset + 1] = static_cast<uint8_t>(galois_multiply(a0, 0x09) ^ galois_multiply(a1, 0x0e) ^
                                                                    galois_multiply(a2, 0x0b) ^ galois_multiply(a3, 0x0d));
            schedule[destination_offset + 2] = static_cast<uint8_t>(galois_multiply(a0, 0x0d) ^ galois_multiply(a1, 0x09) ^
                                                                    galois_multiply(a2, 0x0e) ^ galois_multiply(a3, 0x0b));
            schedule[destination_offset + 3] = static_cast<uint8_t>(galois_multiply(a0, 0x0b) ^ galois_multiply(a1, 0x0d) ^
                                                                    galois_multiply(a2, 0x09) ^ galois_multiply(a3, 0x0e));
        }

        std::array<uint8_t, aes_schedule_size> build_aes128_schedule(const std::span<const uint8_t, aes_128_key_size> raw_key)
        {
            std::array<uint8_t, aes_schedule_size> schedule{};
            std::memcpy(schedule.data(), raw_key.data(), raw_key.size());

            uint8_t round_constant = 1;
            for (size_t round = 1; round <= 10; ++round)
            {
                const size_t previous_offset = (round - 1) * aes_128_key_size;
                const size_t current_offset = round * aes_128_key_size;
                std::array<uint8_t, 4> transformed = {
                    aes_sbox(schedule[previous_offset + 13]),
                    aes_sbox(schedule[previous_offset + 14]),
                    aes_sbox(schedule[previous_offset + 15]),
                    aes_sbox(schedule[previous_offset + 12]),
                };
                transformed[0] ^= round_constant;
                for (size_t byte = 0; byte < transformed.size(); ++byte)
                {
                    schedule[current_offset + byte] = schedule[previous_offset + byte] ^ transformed[byte];
                }
                for (size_t word = 1; word < 4; ++word)
                {
                    const size_t word_offset = word * 4;
                    for (size_t byte = 0; byte < 4; ++byte)
                    {
                        schedule[current_offset + word_offset + byte] =
                            schedule[previous_offset + word_offset + byte] ^ schedule[current_offset + word_offset - 4 + byte];
                    }
                }
                round_constant = galois_multiply(round_constant, 2);
            }

            for (size_t round = 1; round < 10; ++round)
            {
                const size_t source_offset = round * aes_128_key_size;
                const size_t destination_offset = 0x130 - (round - 1) * aes_128_key_size;
                for (size_t column = 0; column < 4; ++column)
                {
                    write_inverse_mix_columns(schedule, destination_offset + column * 4, source_offset + column * 4);
                }
            }
            std::memcpy(schedule.data() + 0x140, schedule.data(), aes_128_key_size);
            return schedule;
        }

        std::array<uint8_t, opaque_blob_size> build_kssm_blob(const std::span<const uint8_t, aes_128_key_size> raw_key)
        {
            std::array<uint8_t, opaque_blob_size> blob{};
            write_value(std::span{blob}, 0x00, static_cast<uint32_t>(opaque_blob_size));
            write_value(std::span{blob}, 0x04, opaque_blob_magic);
            write_value(std::span{blob}, 0x08, opaque_algorithm);
            write_value(std::span{blob}, 0x0c, opaque_mode);
            write_value(std::span{blob}, 0x10, static_cast<uint32_t>(aes_128_key_size));
            write_value(std::span{blob}, 0x14, opaque_flags);
            write_value(std::span{blob}, 0x18, static_cast<uint32_t>(aes_128_key_size));
            std::memcpy(blob.data() + 0x1c, raw_key.data(), raw_key.size());

            const auto schedule = build_aes128_schedule(raw_key);
            std::memcpy(blob.data() + 0x40, schedule.data(), schedule.size());
            write_value(std::span{blob}, 0x210, uint32_t{0xa0});
            write_value(std::span{blob}, 0x214, uint32_t{0x140});
            return blob;
        }

        std::array<uint8_t, ssl3_wrapper_size + opaque_blob_size> build_key_payload(const provider_context_input& input, const bool inbound)
        {
            std::array<uint8_t, ssl3_wrapper_size + opaque_blob_size> payload{};
            const auto& key = inbound ? input.inbound_raw_key : input.outbound_raw_key;
            const auto& fixed_iv = inbound ? input.inbound_fixed_iv : input.outbound_fixed_iv;
            write_value(std::span{payload}, 0x00, static_cast<uint32_t>(payload.size()));
            write_value(std::span{payload}, 0x04, ssl3_magic);
            write_value(std::span{payload}, 0x08, input.protocol);
            write_value(std::span{payload}, 0x0c, input.cipher_suite);
            write_value(std::span{payload}, 0x10, uint32_t{inbound ? 1U : 0U});
            write_value(std::span{payload}, 0x14, static_cast<uint32_t>(opaque_blob_size));
            write_value(std::span{payload}, 0x18, uint32_t{4});
            std::memcpy(payload.data() + 0x1c, fixed_iv.data(), fixed_iv.size());
            write_value(std::span{payload}, 0x4c, uint32_t{0});
            const auto blob = build_kssm_blob(key);
            std::memcpy(payload.data() + ssl3_wrapper_size, blob.data(), blob.size());
            return payload;
        }

        bool append_certificate_property(std::vector<uint8_t>& result, const uint32_t property, const std::span<const uint8_t> payload)
        {
            if (payload.size() > std::numeric_limits<uint32_t>::max() ||
                result.size() > std::numeric_limits<size_t>::max() - 12 - payload.size())
            {
                return false;
            }

            const size_t offset = result.size();
            result.resize(offset + 12 + payload.size());
            auto output = std::span{result}.subspan(offset);
            write_value(output, 0, property);
            write_value(output, 4, uint32_t{1});
            write_value(output, 8, static_cast<uint32_t>(payload.size()));
            std::memcpy(output.data() + 12, payload.data(), payload.size());
            return true;
        }

        std::optional<std::array<uint8_t, 20>> certificate_sha1(const std::span<const uint8_t> certificate)
        {
            std::array<uint8_t, 20> result{};
            unsigned int size{};
            if (EVP_Digest(certificate.data(), certificate.size(), result.data(), &size, EVP_sha1(), nullptr) != 1 || size != result.size())
            {
                return std::nullopt;
            }
            return result;
        }

        std::optional<uint64_t> certificate_file_time(const std::span<const uint8_t> certificate, const bool not_before)
        {
            if (certificate.empty())
            {
                return std::nullopt;
            }

            const unsigned char* encoded = certificate.data();
            std::unique_ptr<X509, decltype(&X509_free)> parsed{d2i_X509(nullptr, &encoded, certificate.size()), X509_free};
            if (!parsed || encoded != certificate.data() + certificate.size())
            {
                return std::nullopt;
            }

            const ASN1_TIME* time = not_before ? X509_get0_notBefore(parsed.get()) : X509_get0_notAfter(parsed.get());
            std::tm broken_down{};
            if (time == nullptr || ASN1_TIME_to_tm(time, &broken_down) != 1)
            {
                return std::nullopt;
            }

            const auto date = std::chrono::year{broken_down.tm_year + 1900} /
                              std::chrono::month{static_cast<unsigned int>(broken_down.tm_mon + 1)} /
                              std::chrono::day{static_cast<unsigned int>(broken_down.tm_mday)};
            if (!date.ok())
            {
                return std::nullopt;
            }

            constexpr int64_t unix_to_windows_seconds = 11644473600;
            const int64_t seconds = std::chrono::sys_days{date}.time_since_epoch().count() * 86400LL + broken_down.tm_hour * 3600LL +
                                    broken_down.tm_min * 60LL + broken_down.tm_sec;
            if (seconds < -unix_to_windows_seconds)
            {
                return std::nullopt;
            }
            const uint64_t windows_seconds = static_cast<uint64_t>(seconds + unix_to_windows_seconds);
            if (windows_seconds > std::numeric_limits<uint64_t>::max() / 10000000ULL)
            {
                return std::nullopt;
            }
            return windows_seconds * 10000000ULL;
        }

        std::optional<std::vector<uint8_t>> build_serialized_chain_context(const std::vector<std::vector<uint8_t>>& peer_certificates)
        {
            constexpr size_t certificate_count = 3;
            constexpr size_t oid_count = 7;
            constexpr std::array<uint32_t, oid_count> oid_offsets = {0, 25, 40, 58, 76, 94, 112};
            constexpr std::array<std::string_view, oid_count> oids = {
                "1.3.6.1.4.1.6449.1.2.2.7", "2.23.140.1.2.1",    "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.1",
                "1.3.6.1.5.5.7.3.2",        "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1",
            };
            constexpr size_t element_end = serialized_chain_context_header_size + certificate_count * serialized_chain_context_element_size;
            constexpr size_t string_offset = element_end + oid_count * sizeof(uint32_t);
            constexpr size_t string_size = 130;
            constexpr size_t size = string_offset + string_size;
            if (peer_certificates.size() != certificate_count)
            {
                return std::nullopt;
            }

            const auto not_before = certificate_file_time(peer_certificates.front(), true);
            const auto not_after = certificate_file_time(peer_certificates.front(), false);
            if (!not_before || !not_after)
            {
                return std::nullopt;
            }

            std::vector<uint8_t> result(size);
            auto output = std::span{result};
            write_value(output, 0x00, serialized_chain_context_magic);
            write_value(output, 0x04, static_cast<uint32_t>(size));
            write_value(output, 0x08, static_cast<uint32_t>(serialized_chain_context_header_size));
            write_value(output, 0x0c, static_cast<uint32_t>(serialized_chain_context_element_size));
            write_value(output, 0x10, static_cast<uint32_t>(certificate_count));
            write_value(output, 0x14, static_cast<uint32_t>(oid_count));
            write_value(output, 0x18, static_cast<uint32_t>(string_offset));
            write_value(output, 0x1c, static_cast<uint32_t>(string_size));
            write_value(output, 0x20, uint32_t{0});
            write_value(output, 0x24, uint32_t{0x100});
            write_value(output, 0x28, *not_before);
            write_value(output, 0x30, *not_after);

            constexpr std::array<uint32_t, certificate_count> trust_info = {0x102, 0x102, 0x10c};
            constexpr std::array<uint32_t, certificate_count> first_usage = {2, 3, 5};
            constexpr std::array<uint32_t, certificate_count> second_usage = {1, 2, 2};
            constexpr std::array<uint32_t, certificate_count> first_usage_count = {2, std::numeric_limits<uint32_t>::max(),
                                                                                   std::numeric_limits<uint32_t>::max()};
            for (size_t index = 0; index < certificate_count; ++index)
            {
                const auto sha1 = certificate_sha1(peer_certificates[index]);
                if (!sha1)
                {
                    return std::nullopt;
                }

                const size_t offset = serialized_chain_context_header_size + index * serialized_chain_context_element_size;
                write_value(output, offset, static_cast<uint32_t>(serialized_chain_context_element_size));
                write_value(output, offset + 0x0c, trust_info[index]);
                write_value(output, offset + 0x10, first_usage_count[index]);
                write_value(output, offset + 0x14, uint32_t{0});
                write_value(output, offset + 0x18, second_usage[index]);
                write_value(output, offset + 0x1c, first_usage[index]);
                std::memcpy(output.data() + offset + 0x20, sha1->data(), sha1->size());
            }

            for (size_t index = 0; index < oid_count; ++index)
            {
                write_value(output, element_end + index * sizeof(uint32_t), oid_offsets[index]);
            }
            size_t offset = string_offset;
            for (const auto oid : oids)
            {
                std::memcpy(output.data() + offset, oid.data(), oid.size());
                offset += oid.size();
                output[offset++] = 0;
            }
            return result;
        }

        std::optional<std::vector<uint8_t>> build_certificate_store(const std::vector<std::vector<uint8_t>>& peer_certificates)
        {
            if (peer_certificates.empty() || peer_certificates.size() > std::numeric_limits<uint32_t>::max())
            {
                return std::nullopt;
            }

            const auto chain_context = build_serialized_chain_context(peer_certificates);
            constexpr std::array<uint8_t, 8> header = {0, 0, 0, 0, 'C', 'E', 'R', 'T'};
            std::vector<uint8_t> result{header.begin(), header.end()};
            for (size_t index = peer_certificates.size(); index-- > 0;)
            {
                if (index == 0 && chain_context && !append_certificate_property(result, serialized_chain_context_property, *chain_context))
                {
                    return std::nullopt;
                }

                const auto& certificate = peer_certificates[index];
                if (certificate.empty())
                {
                    return std::nullopt;
                }

                std::array<uint8_t, sizeof(uint32_t)> serialized_index{};
                write_value(std::span{serialized_index}, 0, static_cast<uint32_t>(index));

                const auto sha1 = certificate_sha1(certificate);
                if (!sha1 || !append_certificate_property(result, serialized_chain_index_property, serialized_index) ||
                    !append_certificate_property(result, serialized_sha1_property, *sha1) ||
                    !append_certificate_property(result, serialized_certificate_property, certificate))
                {
                    return std::nullopt;
                }
            }

            result.resize(result.size() + 12);
            if (result.size() > std::numeric_limits<uint32_t>::max())
            {
                return std::nullopt;
            }
            return result;
        }

        void append_item(std::vector<uint8_t>& result, const uint32_t type, const std::span<const uint8_t> payload,
                         const uint32_t reported_size)
        {
            const size_t offset = result.size();
            const size_t padded_size = (payload.size() + 7) & ~size_t{7};
            result.resize(offset + 16 + padded_size);
            auto output = std::span{result}.subspan(offset);
            write_value(output, 0, type);
            write_value(output, 4, static_cast<uint32_t>(padded_size));
            write_value(output, 8, reported_size);
            write_value(output, 12, uint32_t{0});
            std::memcpy(output.data() + 16, payload.data(), payload.size());
        }

    }

    tls_record_framing frame_tls_records(const std::span<const uint8_t> bytes)
    {
        if (bytes.empty())
        {
            return {.missing_size = tls_record_header_size};
        }

        size_t offset{};
        while (offset < bytes.size())
        {
            const size_t remaining = bytes.size() - offset;
            if (remaining < tls_record_header_size)
            {
                return {.complete_size = offset, .missing_size = tls_record_header_size - remaining};
            }
            const size_t record_size = tls_record_header_size + (static_cast<size_t>(bytes[offset + 3]) << 8) + bytes[offset + 4];
            if (record_size > remaining)
            {
                return {.complete_size = offset, .missing_size = record_size - remaining};
            }
            offset += record_size;
        }
        return {.complete_size = offset};
    }

    bool tls_record_counter::observe(const std::span<const uint8_t> record)
    {
        const auto framing = frame_tls_records(record);
        const size_t record_size =
            record.size() < tls_record_header_size ? 0 : tls_record_header_size + (static_cast<size_t>(record[3]) << 8) + record[4];
        if (framing.missing_size != 0 || framing.complete_size != record.size() || record_size != record.size())
        {
            return false;
        }
        if (record[0] == 20)
        {
            active_ = true;
        }
        else if (active_)
        {
            ++value_;
        }
        return true;
    }

    uint64_t tls_record_counter::value() const
    {
        return value_;
    }

    std::optional<std::vector<uint8_t>> build_provider_context(const provider_context_input& input)
    {
        if (input.protocol != tls_1_2 || input.cipher_suite != tls_ecdhe_ecdsa_with_aes_128_gcm_sha256)
        {
            return std::nullopt;
        }

        std::array<uint8_t, 200> packed{};
        write_value(std::span{packed}, 0x00, uint32_t{4});
        write_value(std::span{packed}, 0x04, uint32_t{1});
        write_value(std::span{packed}, 0x08, input.serialized_context_flags);
        write_value(std::span{packed}, 0x10, uint32_t{0x800});
        write_value(std::span{packed}, 0x14, input.cipher_suite);
        write_value(std::span{packed}, 0x18, uint32_t{0x17});
        write_value(std::span{packed}, 0x1c, uint32_t{0x100});
        write_value(std::span{packed}, 0x20, uint32_t{8});
        write_value(std::span{packed}, 0x24, uint32_t{8});
        write_value(std::span{packed}, 0x2c, uint32_t{1});
        write_value(std::span{packed}, 0x30, input.inbound_sequence);
        write_value(std::span{packed}, 0x38, input.outbound_sequence);
        write_value(std::span{packed}, 0x98, uint32_t{5});
        write_value(std::span{packed}, 0xb0, uint32_t{0xffffffff});

        constexpr std::u16string_view provider_name = u"Microsoft SSL Protocol Provider";
        std::array<uint8_t, 64> provider{};
        std::memcpy(provider.data(), provider_name.data(), provider_name.size() * sizeof(char16_t));
        const auto inbound = build_key_payload(input, true);
        const auto outbound = build_key_payload(input, false);
        const auto certificate_store = build_certificate_store(input.peer_certificates);
        if (!certificate_store)
        {
            return std::nullopt;
        }

        std::vector<uint8_t> result;
        result.reserve(1647 + certificate_store->size());
        append_item(result, serialized_packed_context, packed, 0);
        append_item(result, serialized_provider_name, provider, static_cast<uint32_t>(provider.size()));
        append_item(result, serialized_read_key, inbound, static_cast<uint32_t>(inbound.size()));
        append_item(result, serialized_write_key, outbound, static_cast<uint32_t>(outbound.size()));
        append_item(result, serialized_remote_certificate, *certificate_store, static_cast<uint32_t>(certificate_store->size()));
        append_item(result, 0, {}, 0);
        return result;
    }
}
