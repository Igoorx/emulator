#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>

namespace
{
    bool fail(const char* operation)
    {
        std::printf("FAIL: %s (error %lu)\n", operation, GetLastError());
        return false;
    }

    bool test_committed_section_aliases()
    {
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto granularity = static_cast<SIZE_T>(system_info.dwAllocationGranularity);
        const auto mapping_size = granularity * 2;

        HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<DWORD>(mapping_size), nullptr);
        if (!mapping)
        {
            return fail("CreateFileMappingW(SEC_COMMIT)");
        }

        auto* first = static_cast<unsigned char*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size));
        auto* second = static_cast<unsigned char*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size));
        auto* offset_view =
            static_cast<unsigned char*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, static_cast<DWORD>(granularity), granularity));
        if (!first || !second || !offset_view)
        {
            if (offset_view)
            {
                UnmapViewOfFile(offset_view);
            }
            if (second)
            {
                UnmapViewOfFile(second);
            }
            if (first)
            {
                UnmapViewOfFile(first);
            }
            CloseHandle(mapping);
            return fail("MapViewOfFile");
        }

        constexpr unsigned char first_value = 0x39;
        constexpr unsigned char offset_value = 0xA7;
        first[0] = first_value;
        first[granularity] = offset_value;
        const bool aliases_match = second[0] == first_value && second[granularity] == offset_value && offset_view[0] == offset_value;

        const bool handle_closed = CloseHandle(mapping) != FALSE;
        const bool first_unmapped = UnmapViewOfFile(first) != FALSE;
        second[granularity + 1] = 0x5C;
        const bool surviving_alias_matches = offset_view[1] == 0x5C;

        const bool offset_unmapped = UnmapViewOfFile(offset_view) != FALSE;
        const bool second_unmapped = UnmapViewOfFile(second) != FALSE;
        return aliases_match && handle_closed && first_unmapped && surviving_alias_matches && offset_unmapped && second_unmapped;
    }

    bool test_reserved_section_commit()
    {
        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        const auto page_size = static_cast<SIZE_T>(system_info.dwPageSize);

        HANDLE mapping =
            CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_RESERVE, 0, static_cast<DWORD>(page_size * 2), nullptr);
        if (!mapping)
        {
            return fail("CreateFileMappingW(SEC_RESERVE)");
        }

        auto* view = static_cast<unsigned char*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, page_size * 2));
        if (!view)
        {
            CloseHandle(mapping);
            return fail("MapViewOfFile(SEC_RESERVE)");
        }

        MEMORY_BASIC_INFORMATION before{};
        const bool queried_before = VirtualQuery(view + page_size, &before, sizeof(before)) == sizeof(before);
        void* committed = VirtualAlloc(view + page_size, page_size, MEM_COMMIT, PAGE_READWRITE);
        MEMORY_BASIC_INFORMATION after{};
        const bool queried_after = VirtualQuery(view + page_size, &after, sizeof(after)) == sizeof(after);

        bool writable = false;
        if (committed == view + page_size)
        {
            view[page_size] = 0xD4;
            writable = view[page_size] == 0xD4;
        }

        const bool unmapped = UnmapViewOfFile(view) != FALSE;
        const bool handle_closed = CloseHandle(mapping) != FALSE;
        return queried_before && before.State == MEM_RESERVE && committed == view + page_size && queried_after &&
               after.State == MEM_COMMIT && writable && unmapped && handle_closed;
    }
}

int main()
{
    if (!test_committed_section_aliases())
    {
        std::puts("FAIL: committed pagefile-section alias behavior");
        return 1;
    }

    if (!test_reserved_section_commit())
    {
        std::puts("FAIL: SEC_RESERVE commit behavior");
        return 1;
    }

    std::puts("PASS");
    return 0;
}
