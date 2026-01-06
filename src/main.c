#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// Helper: Convert RVA to File Offset
DWORD rva_to_offset(PIMAGE_NT_HEADERS p_nt_headers, DWORD rva) {
    PIMAGE_SECTION_HEADER p_section_header = IMAGE_FIRST_SECTION(p_nt_headers);
    for (int i = 0; i < p_nt_headers->FileHeader.NumberOfSections; i++) {
        if (rva >= p_section_header[i].VirtualAddress &&
            rva < (p_section_header[i].VirtualAddress + p_section_header[i].Misc.VirtualSize)) {
            return (rva - p_section_header[i].VirtualAddress) + p_section_header[i].PointerToRawData;
        }
    }
    return 0;
}

BOOL is_ntdll(const char* filePath) {
    BOOL is_ntdll = FALSE;
    HANDLE h_file = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_file == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE h_mapping = CreateFileMapping(h_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h_mapping) { CloseHandle(h_file); return FALSE; }

    LPBYTE p_base = (LPBYTE)MapViewOfFile(h_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!p_base) { CloseHandle(h_mapping); CloseHandle(h_file); return FALSE; }

    // 1. Basic PE Validation
    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)p_base;
    if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;

    PIMAGE_NT_HEADERS p_nt_headers = (PIMAGE_NT_HEADERS)(p_base + p_dos_header->e_lfanew);
    if (p_nt_headers->Signature != IMAGE_NT_SIGNATURE) goto cleanup;

    // 2. Locate Export Directory
    IMAGE_DATA_DIRECTORY export_data_dir = p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir.VirtualAddress == 0) goto cleanup;

    DWORD export_offset = rva_to_offset(p_nt_headers, export_data_dir.VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY p_export_dir = (PIMAGE_EXPORT_DIRECTORY)(p_base + export_offset);

    // 3. Check Internal Name ("ntdll.dll")
    DWORD name_offset = rva_to_offset(p_nt_headers, p_export_dir->Name);
    if (name_offset && StrCmpICA((char*)(p_base + name_offset), "ntdll.dll") == 0) {
        
        // 4. Robust Check: Verify "NtClose" exists in the export list
        DWORD names_array_offset = rva_to_offset(p_nt_headers, p_export_dir->AddressOfNames);
        DWORD* p_names_array = (DWORD*)(p_base + names_array_offset);

        for (DWORD i = 0; i < p_export_dir->NumberOfNames; i++) {
            DWORD currentname_offset = rva_to_offset(p_nt_headers, p_names_array[i]);
            if (currentname_offset == 0) continue;

            const char* func_name = (const char*)(p_base + currentname_offset);
            
            // Check for "NtClose" - arguably the most stable export in NT history
            if (strcmp(func_name, "NtClose") == 0) {
                is_ntdll = TRUE;
                break;
            }
        }
    }

cleanup:
    UnmapViewOfFile(p_base);
    CloseHandle(h_mapping);
    CloseHandle(h_file);
    return is_ntdll;
}

int main() {
    const char* path = "C:\\Windows\\System32\\ntdll.dll";
    if (is_ntdll(path)) {
        printf("[+] Verified: File is ntdll.dll\n");
    } else {
        printf("[-] Verification Failed: File is NOT ntdll.dll\n");
    }
    return 0;
}