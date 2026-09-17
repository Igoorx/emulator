#include "../windows-emulator/ports/sspi_context.hpp"

#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <cstring>
#include <filesystem>
#include <fstream>

namespace
{
    template <typename T>
    T read_value(const std::span<const uint8_t> bytes, const size_t offset)
    {
        T value{};
        std::memcpy(&value, bytes.data() + offset, sizeof(value));
        return value;
    }

    std::vector<uint8_t> read_capture()
    {
        const std::filesystem::path path =
            std::filesystem::path{SOGEN_SOURCE_DIR} / "sspi_port_handoff/windows_capture/capture/sspi/isc_0006_output_context.bin";
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        if (!stream)
        {
            return {};
        }
        const auto size = stream.tellg();
        if (size < 0)
        {
            return {};
        }
        std::vector<uint8_t> result(static_cast<size_t>(size));
        stream.seekg(0);
        stream.read(reinterpret_cast<char*>(result.data()), size);
        return result;
    }

    struct item
    {
        uint32_t type{};
        uint32_t padded_size{};
        uint32_t reported_size{};
        std::span<const uint8_t> payload{};
    };

    std::vector<item> parse_items(const std::span<const uint8_t> bytes)
    {
        std::vector<item> result;
        size_t offset{};
        while (offset + 16 <= bytes.size())
        {
            item current{
                .type = read_value<uint32_t>(bytes, offset),
                .padded_size = read_value<uint32_t>(bytes, offset + 4),
                .reported_size = read_value<uint32_t>(bytes, offset + 8),
            };
            if (current.padded_size > bytes.size() - offset - 16)
            {
                return {};
            }
            current.payload = bytes.subspan(offset + 16, current.padded_size);
            result.push_back(current);
            offset += 16 + current.padded_size;
            if (current.type == 0)
            {
                break;
            }
        }
        return offset == bytes.size() ? result : std::vector<item>{};
    }

    std::span<const uint8_t> captured_certificate_store()
    {
        static const std::vector<uint8_t> capture = read_capture();
        static const std::vector<item> items = parse_items(capture);
        if (items.size() < 5 || items[4].type != 0x15 || items[4].reported_size > items[4].payload.size())
        {
            return {};
        }
        return items[4].payload.first(items[4].reported_size);
    }

    std::vector<std::vector<uint8_t>> certificate_chain(const std::span<const uint8_t> store)
    {
        constexpr uint32_t chain_index_property = 0xe697;
        constexpr uint32_t certificate_property = 0x20;
        if (store.size() < 20 || std::memcmp(store.data(), "\0\0\0\0CERT", 8) != 0)
        {
            return {};
        }

        std::vector<std::vector<uint8_t>> result;
        std::optional<uint32_t> chain_index;
        size_t offset = 8;
        while (offset + 12 <= store.size())
        {
            const uint32_t property = read_value<uint32_t>(store, offset);
            const uint32_t marker = read_value<uint32_t>(store, offset + 4);
            const uint32_t size = read_value<uint32_t>(store, offset + 8);
            offset += 12;
            if (property == 0)
            {
                return marker == 0 && size == 0 ? result : std::vector<std::vector<uint8_t>>{};
            }
            if (marker != 1 || size > store.size() - offset)
            {
                return {};
            }
            if (property == chain_index_property && size == sizeof(uint32_t))
            {
                chain_index = read_value<uint32_t>(store, offset);
            }
            else if (property == certificate_property)
            {
                if (!chain_index)
                {
                    return {};
                }
                if (result.size() <= *chain_index)
                {
                    result.resize(static_cast<size_t>(*chain_index) + 1);
                }
                result[*chain_index].assign(store.begin() + static_cast<std::ptrdiff_t>(offset),
                                            store.begin() + static_cast<std::ptrdiff_t>(offset + size));
                chain_index.reset();
            }
            offset += size;
        }
        return {};
    }

    std::vector<uint8_t> captured_certificate_store_without_status()
    {
        constexpr uint32_t certificate_status_property = 0x77;
        const auto store = captured_certificate_store();
        if (store.size() < 20)
        {
            return {};
        }

        std::vector<uint8_t> result(store.begin(), store.begin() + 8);
        size_t offset = 8;
        while (offset + 12 <= store.size())
        {
            const uint32_t property = read_value<uint32_t>(store, offset);
            const uint32_t size = read_value<uint32_t>(store, offset + 8);
            if (size > store.size() - offset - 12)
            {
                return {};
            }
            if (property != certificate_status_property)
            {
                result.insert(result.end(), store.begin() + static_cast<std::ptrdiff_t>(offset),
                              store.begin() + static_cast<std::ptrdiff_t>(offset + 12 + size));
            }
            offset += 12 + size;
            if (property == 0)
            {
                return result;
            }
        }
        return {};
    }

    std::span<const uint8_t> certificate_store_property(const std::span<const uint8_t> store, const uint32_t requested_property)
    {
        size_t offset = 8;
        while (offset + 12 <= store.size())
        {
            const uint32_t property = read_value<uint32_t>(store, offset);
            const uint32_t size = read_value<uint32_t>(store, offset + 8);
            offset += 12;
            if (property == 0 || size > store.size() - offset)
            {
                return {};
            }
            if (property == requested_property)
            {
                return store.subspan(offset, size);
            }
            offset += size;
        }
        return {};
    }

    std::array<uint8_t, 20> certificate_sha1(const std::span<const uint8_t> certificate)
    {
        std::array<uint8_t, 20> result{};
        unsigned int size{};
        EXPECT_EQ(EVP_Digest(certificate.data(), certificate.size(), result.data(), &size, EVP_sha1(), nullptr), 1);
        EXPECT_EQ(size, result.size());
        return result;
    }

    sogen::sspi::provider_context_input fixture_input()
    {
        return {
            .protocol = 0x0303,
            .cipher_suite = 0xc02b,
            .inbound_raw_key = {0x0e, 0x83, 0x0f, 0x61, 0x15, 0x4b, 0x85, 0xf9, 0x16, 0xf4, 0x39, 0x79, 0xc5, 0xd1, 0xfd, 0xc2},
            .inbound_fixed_iv = {0x6a, 0xc8, 0xe2, 0xda},
            .inbound_sequence = 1,
            .outbound_raw_key = {0x43, 0xad, 0xea, 0x9e, 0x4a, 0x6b, 0xbf, 0x85, 0xa1, 0x7b, 0x0d, 0x97, 0xf1, 0x33, 0x2e, 0xac},
            .outbound_fixed_iv = {0xba, 0x79, 0x03, 0xb0},
            .outbound_sequence = 1,
            .serialized_context_flags = 0x0000000008008200,
            .peer_certificates = certificate_chain(captured_certificate_store()),
        };
    }
}

TEST(sspi_context, builds_provider_context_with_remote_certificate)
{
    const auto generated = sogen::sspi::build_provider_context(fixture_input());
    ASSERT_TRUE(generated);
    const auto expected_certificate_store = captured_certificate_store_without_status();
    ASSERT_EQ(expected_certificate_store.size(), 2919);
    EXPECT_EQ(generated->size(), 1624 + 16 + 3424);

    const auto items = parse_items(*generated);
    ASSERT_EQ(items.size(), 6);
    EXPECT_EQ(items[0].type, 1);
    EXPECT_EQ(items[0].padded_size, 200);
    EXPECT_EQ(items[0].reported_size, 0);
    EXPECT_EQ(items[1].type, 9);
    EXPECT_EQ(items[1].padded_size, 64);
    EXPECT_EQ(items[2].type, 2);
    EXPECT_EQ(items[2].padded_size, 640);
    EXPECT_EQ(items[3].type, 3);
    EXPECT_EQ(items[3].padded_size, 640);
    EXPECT_EQ(items[4].type, 0x15);
    EXPECT_EQ(items[4].padded_size, 3424);
    EXPECT_EQ(items[4].reported_size, 3417);
    EXPECT_EQ(items[5].type, 0);

    const auto packed = items[0].payload;
    EXPECT_EQ(read_value<uint32_t>(packed, 0x00), 4);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x04), 1);
    EXPECT_EQ(read_value<uint64_t>(packed, 0x08), 0x0000000008008200);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x10), 0x800);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x14), 0xc02b);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x18), 0x17);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x1c), 0x100);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x20), 8);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x24), 8);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x2c), 1);
    EXPECT_EQ(read_value<uint64_t>(packed, 0x30), 1);
    EXPECT_EQ(read_value<uint64_t>(packed, 0x38), 1);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x50), 0);
    EXPECT_EQ(read_value<uint32_t>(packed, 0x98), 5);
    EXPECT_EQ(read_value<uint32_t>(packed, 0xb0), 0xffffffff);
}

TEST(sspi_context, key_records_match_native_capture_oracle)
{
    const auto capture = read_capture();
    ASSERT_EQ(capture.size(), 5096);
    const auto captured_items = parse_items(capture);
    ASSERT_EQ(captured_items.size(), 7);

    const auto generated = sogen::sspi::build_provider_context(fixture_input());
    ASSERT_TRUE(generated);
    const auto generated_items = parse_items(*generated);
    ASSERT_EQ(generated_items.size(), 6);

    EXPECT_TRUE(std::ranges::equal(generated_items[1].payload, captured_items[1].payload));
    EXPECT_TRUE(std::ranges::equal(generated_items[2].payload, captured_items[2].payload));
    EXPECT_TRUE(std::ranges::equal(generated_items[3].payload, captured_items[3].payload));
    EXPECT_EQ(read_value<uint32_t>(generated_items[2].payload, 0x10), 1);
    EXPECT_EQ(read_value<uint32_t>(generated_items[3].payload, 0x10), 0);
}

TEST(sspi_context, certificate_store_preserves_native_chain_identity)
{
    const auto expected = certificate_chain(captured_certificate_store());
    ASSERT_EQ(expected.size(), 3);

    const auto generated = sogen::sspi::build_provider_context(fixture_input());
    ASSERT_TRUE(generated);
    const auto items = parse_items(*generated);
    ASSERT_EQ(items.size(), 6);
    EXPECT_EQ(certificate_chain(items[4].payload.first(items[4].reported_size)), expected);
}

TEST(sspi_context, serializes_remote_certificate_chain_context)
{
    constexpr size_t header_size = 0xa0;
    constexpr size_t element_size = 0x38;
    constexpr size_t oid_count = 7;
    constexpr size_t string_offset = 0x164;
    constexpr size_t string_size = 0x82;
    const auto input = fixture_input();
    ASSERT_EQ(input.peer_certificates.size(), 3);

    const auto generated = sogen::sspi::build_provider_context(input);
    ASSERT_TRUE(generated);
    const auto items = parse_items(*generated);
    ASSERT_EQ(items.size(), 6);
    const auto store = items[4].payload.first(items[4].reported_size);
    const auto chain_context = certificate_store_property(store, 0x77);
    ASSERT_EQ(chain_context.size(), 486);
    const auto captured_chain_context = certificate_store_property(captured_certificate_store(), 0x77);
    ASSERT_GE(captured_chain_context.size(), header_size);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x20), 0);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x24), 0x100);
    EXPECT_EQ(read_value<uint64_t>(chain_context, 0x28), read_value<uint64_t>(captured_chain_context, 0x28));
    EXPECT_EQ(read_value<uint64_t>(chain_context, 0x30), read_value<uint64_t>(captured_chain_context, 0x30));
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x00), 0x43435343);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x04), chain_context.size());
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x08), header_size);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x0c), element_size);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x10), input.peer_certificates.size());
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x14), oid_count);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x18), string_offset);
    EXPECT_EQ(read_value<uint32_t>(chain_context, 0x1c), string_size);

    constexpr std::array<uint32_t, 3> trust_info = {0x102, 0x102, 0x10c};
    constexpr std::array<uint32_t, 3> first_usage = {2, 3, 5};
    constexpr std::array<uint32_t, 3> second_usage = {1, 2, 2};
    constexpr std::array<uint32_t, 3> first_usage_count = {2, std::numeric_limits<uint32_t>::max(), std::numeric_limits<uint32_t>::max()};
    for (size_t index = 0; index < input.peer_certificates.size(); ++index)
    {
        const size_t offset = header_size + index * element_size;
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset), element_size);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x04), 0);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x08), 0);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x0c), trust_info[index]);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x10), first_usage_count[index]);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x14), 0);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x18), second_usage[index]);
        EXPECT_EQ(read_value<uint32_t>(chain_context, offset + 0x1c), first_usage[index]);
        const auto expected_sha1 = certificate_sha1(input.peer_certificates[index]);
        EXPECT_TRUE(std::ranges::equal(chain_context.subspan(offset + 0x20, expected_sha1.size()), expected_sha1));
    }
}

TEST(sspi_context, rejects_missing_remote_certificate)
{
    auto input = fixture_input();
    input.peer_certificates.clear();
    EXPECT_FALSE(sogen::sspi::build_provider_context(input));
}

TEST(sspi_context, reports_exact_missing_tls_record_bytes)
{
    const std::array<uint8_t, 8> record = {22, 3, 3, 0, 3, 1, 2, 3};
    for (size_t size = 0; size < 5; ++size)
    {
        const auto framing = sogen::sspi::frame_tls_records(std::span{record}.first(size));
        EXPECT_EQ(framing.complete_size, 0);
        EXPECT_EQ(framing.missing_size, 5 - size);
    }

    const auto header_only = sogen::sspi::frame_tls_records(std::span{record}.first(5));
    EXPECT_EQ(header_only.complete_size, 0);
    EXPECT_EQ(header_only.missing_size, 3);
    const auto truncated_payload = sogen::sspi::frame_tls_records(std::span{record}.first(7));
    EXPECT_EQ(truncated_payload.complete_size, 0);
    EXPECT_EQ(truncated_payload.missing_size, 1);
}

TEST(sspi_context, frames_coalesced_records_before_partial_tail)
{
    const std::array<uint8_t, 14> records = {22, 3, 3, 0, 1, 0xaa, 20, 3, 3, 0, 0, 23, 3, 3};
    const auto framing = sogen::sspi::frame_tls_records(records);
    EXPECT_EQ(framing.complete_size, 11);
    EXPECT_EQ(framing.missing_size, 2);
}

TEST(sspi_context, counts_only_post_ccs_owned_records)
{
    const std::array<uint8_t, 5> handshake = {22, 3, 3, 0, 0};
    const std::array<uint8_t, 6> ccs = {20, 3, 3, 0, 1, 1};
    const std::array<uint8_t, 5> application = {23, 3, 3, 0, 0};
    sogen::sspi::tls_record_counter inbound;
    sogen::sspi::tls_record_counter outbound;

    ASSERT_TRUE(inbound.observe(handshake));
    ASSERT_TRUE(outbound.observe(handshake));
    EXPECT_EQ(inbound.value(), 0);
    EXPECT_EQ(outbound.value(), 0);
    ASSERT_TRUE(inbound.observe(ccs));
    ASSERT_TRUE(outbound.observe(ccs));
    EXPECT_EQ(inbound.value(), 0);
    EXPECT_EQ(outbound.value(), 0);
    ASSERT_TRUE(inbound.observe(handshake));
    ASSERT_TRUE(outbound.observe(handshake));
    EXPECT_EQ(inbound.value(), 1);
    EXPECT_EQ(outbound.value(), 1);

    std::array<uint8_t, 10> finished_and_extra{};
    std::memcpy(finished_and_extra.data(), handshake.data(), handshake.size());
    std::memcpy(finished_and_extra.data() + handshake.size(), application.data(), application.size());
    const auto framing = sogen::sspi::frame_tls_records(finished_and_extra);
    ASSERT_EQ(framing.complete_size, finished_and_extra.size());
    ASSERT_FALSE(inbound.observe(finished_and_extra));
    EXPECT_EQ(inbound.value(), 1);
}
