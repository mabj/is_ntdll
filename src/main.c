#include <windows.h>
#include <stdio.h>

// Helper: Convert RVA to File Offset (architecture-agnostic)
DWORD rva_to_offset(PIMAGE_SECTION_HEADER sections, WORD num_sections, DWORD rva) {
    for (WORD i = 0; i < num_sections; i++) {
        if (rva >= sections[i].VirtualAddress &&
            rva < (sections[i].VirtualAddress + sections[i].Misc.VirtualSize)) {
            return (rva - sections[i].VirtualAddress) + sections[i].PointerToRawData;
        }
    }
    return 0;
}

// Check if exports contain NtClose (signature function check)
BOOL check_ntclose_export(LPBYTE p_base, PIMAGE_EXPORT_DIRECTORY p_export_dir, 
                          PIMAGE_SECTION_HEADER sections, WORD num_sections) {
    DWORD names_array_offset = rva_to_offset(sections, num_sections, p_export_dir->AddressOfNames);
    if (names_array_offset == 0) return FALSE;
    
    DWORD* p_names_array = (DWORD*)(p_base + names_array_offset);
    
    for (DWORD i = 0; i < p_export_dir->NumberOfNames; i++) {
        DWORD currentname_offset = rva_to_offset(sections, num_sections, p_names_array[i]);
        if (currentname_offset == 0) continue;
        
        const char* func_name = (const char*)(p_base + currentname_offset);
        
        // Check for "NtClose" - arguably the most stable export in NT history
        if (strcmp(func_name, "NtClose") == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// Verify ntdll for 32-bit PE
BOOL verify_ntdll_32(LPBYTE p_base, PIMAGE_NT_HEADERS32 p_nt_headers32) {
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(p_nt_headers32);
    WORD num_sections = p_nt_headers32->FileHeader.NumberOfSections;
    
    // Locate Export Directory
    IMAGE_DATA_DIRECTORY export_data_dir = p_nt_headers32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir.VirtualAddress == 0) return FALSE;
    
    DWORD export_offset = rva_to_offset(sections, num_sections, export_data_dir.VirtualAddress);
    if (export_offset == 0) return FALSE;
    
    PIMAGE_EXPORT_DIRECTORY p_export_dir = (PIMAGE_EXPORT_DIRECTORY)(p_base + export_offset);
    
    // Check Internal Name
    DWORD name_offset = rva_to_offset(sections, num_sections, p_export_dir->Name);
    if (name_offset == 0) return FALSE;
    if (_stricmp((char*)(p_base + name_offset), "ntdll.dll") != 0) return FALSE;
    
    // Verify NtClose export exists
    return check_ntclose_export(p_base, p_export_dir, sections, num_sections);
}

// Verify ntdll for 64-bit PE
BOOL verify_ntdll_64(LPBYTE p_base, PIMAGE_NT_HEADERS64 p_nt_headers64) {
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(p_nt_headers64);
    WORD num_sections = p_nt_headers64->FileHeader.NumberOfSections;
    
    // Locate Export Directory
    IMAGE_DATA_DIRECTORY export_data_dir = p_nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir.VirtualAddress == 0) return FALSE;
    
    DWORD export_offset = rva_to_offset(sections, num_sections, export_data_dir.VirtualAddress);
    if (export_offset == 0) return FALSE;
    
    PIMAGE_EXPORT_DIRECTORY p_export_dir = (PIMAGE_EXPORT_DIRECTORY)(p_base + export_offset);
    
    // Check Internal Name
    DWORD name_offset = rva_to_offset(sections, num_sections, p_export_dir->Name);
    if (name_offset == 0) return FALSE;
    if (_stricmp((char*)(p_base + name_offset), "ntdll.dll") != 0) return FALSE;
    
    // Verify NtClose export exists
    return check_ntclose_export(p_base, p_export_dir, sections, num_sections);
}

BOOL is_ntdll(const char* filePath) {
    BOOL is_ntdll = FALSE;
    HANDLE h_file = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_file == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE h_mapping = CreateFileMapping(h_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!h_mapping) { CloseHandle(h_file); return FALSE; }

    LPBYTE p_base = (LPBYTE)MapViewOfFile(h_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!p_base) { CloseHandle(h_mapping); CloseHandle(h_file); return FALSE; }

    // 1. Basic PE Validation - DOS Header
    PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)p_base;
    if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE) goto cleanup;

    // 2. Validate PE Signature
    DWORD pe_offset = p_dos_header->e_lfanew;
    if (*(DWORD*)(p_base + pe_offset) != IMAGE_NT_SIGNATURE) goto cleanup;
    
    // 3. Read FileHeader to determine architecture
    PIMAGE_FILE_HEADER p_file_header = (PIMAGE_FILE_HEADER)(p_base + pe_offset + sizeof(DWORD));
    WORD machine = p_file_header->Machine;
    
    // 4. Branch based on architecture
    if (machine == IMAGE_FILE_MACHINE_AMD64) {
        // 64-bit PE
        PIMAGE_NT_HEADERS64 p_nt_headers64 = (PIMAGE_NT_HEADERS64)(p_base + pe_offset);
        is_ntdll = verify_ntdll_64(p_base, p_nt_headers64);
    }
    else if (machine == IMAGE_FILE_MACHINE_I386) {
        // 32-bit PE
        PIMAGE_NT_HEADERS32 p_nt_headers32 = (PIMAGE_NT_HEADERS32)(p_base + pe_offset);
        is_ntdll = verify_ntdll_32(p_base, p_nt_headers32);
    }
    else {
        // printf("[-] Unsupported architecture: 0x%X\n", machine);
    }

cleanup:
    UnmapViewOfFile(p_base);
    CloseHandle(h_mapping);
    CloseHandle(h_file);
    return is_ntdll;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        printf("Example: %s C:\\Windows\\System32\\ntdll.dll\n", argv[0]);
        printf("         %s C:\\Windows\\SysWOW64\\ntdll.dll\n", argv[0]);
        return 1;
    }

    const char* path = argv[1];
    printf("[*] Checking: %s\n", path);
    
    if (is_ntdll(path)) {
        printf("TRUE\n");
    } else {
        printf("FALSE\n");
    }
    return 0;
}