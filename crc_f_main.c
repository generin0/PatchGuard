#include "crc_f.h"
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <psapi.h>

static pe_crc_info_t crc_info;
static CRITICAL_SECTION crc_critical_section;
static volatile int monitoring_active = 1;

static void generate_crc32_table(uint32_t* table) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
            }
            else {
                crc = crc >> 1;
            }
        }
        table[i] = crc;
    }
}

uint32_t calculate_pe_crc(uint8_t* base_address, size_t image_size) {
    static uint32_t table[256];
    static int table_generated = 0;

    if (!table_generated) {
        generate_crc32_table(table);
        table_generated = 1;
    }

    uint32_t crc = 0xFFFFFFFF;

    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base_address;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(base_address + dos_header->e_lfanew);

    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_headers);

    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        if (section_header[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            uint8_t* section_start = base_address + section_header[i].VirtualAddress;
            size_t section_size = section_header[i].Misc.VirtualSize;

            for (size_t j = 0; j < section_size; j++) {
                uint8_t byte = section_start[j];
                uint8_t index = (crc ^ byte) & 0xFF;
                crc = (crc >> 8) ^ table[index];
            }
        }
    }

    return crc ^ 0xFFFFFFFF;
}

static int get_module_info(HMODULE module, uint8_t** base_address, size_t* image_size) {
    MODULEINFO module_info;

    if (!GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info))) {
        return 0;
    }

    *base_address = (uint8_t*)module_info.lpBaseOfDll;
    *image_size = module_info.SizeOfImage;
    return 1;
}

int pe_crc_init(void) {
    InitializeCriticalSection(&crc_critical_section);

    crc_info.module_handle = GetModuleHandle(NULL);
    if (!crc_info.module_handle) {
        return 0;
    }

    if (!get_module_info(crc_info.module_handle, &crc_info.image_base, &crc_info.image_size)) {
        return 0;
    }

    crc_info.original_crc = calculate_pe_crc(crc_info.image_base, crc_info.image_size);

    puts(" ");
    printf("PE CRC Protection Initialized:\n");
    printf("Base Address: 0x%p\n", crc_info.image_base);
    printf("Image Size: %zu bytes\n", crc_info.image_size);
    printf("Original CRC: 0x%08X\n", crc_info.original_crc);
    puts(" ");

    HANDLE thread = CreateThread(NULL, 0, pe_crc_monitor_thread, NULL, 0, NULL);
    if (!thread) {
        return 0;
    }

    CloseHandle(thread);
    return 1;
}

DWORD WINAPI pe_crc_monitor_thread(LPVOID lpParam) {
    printf("[+] CRC Monitoring Thread Started\n");

    while (monitoring_active) {
        Sleep(CHECK_INTERVAL_MS);

        EnterCriticalSection(&crc_critical_section);

        uint8_t* current_base;
        size_t current_size;
        if (get_module_info(crc_info.module_handle, &current_base, &current_size)) {

            if (current_base != crc_info.image_base || current_size != crc_info.image_size) {
                printf("[-] PE image relocated or resized! Integrity violation!\n");
                pe_crc_integrity_violation();
            }
            else {
                uint32_t current_crc = calculate_pe_crc(crc_info.image_base, crc_info.image_size);
                if (current_crc != crc_info.original_crc) {
                    printf("[-] CRC Mismatch! Original: 0x%08X, Current: 0x%08X\n",
                    crc_info.original_crc, current_crc);
                    pe_crc_integrity_violation();
                }
            }
        }

        LeaveCriticalSection(&crc_critical_section);
    }

    return 0;
}

void pe_crc_integrity_violation(void) {
    printf("PE Integrity Violation Detected!\n");
    ExitProcess(0xDEADC0DE);
}

void pe_crc_stop(void) {
    monitoring_active = 0;
    DeleteCriticalSection(&crc_critical_section);
}