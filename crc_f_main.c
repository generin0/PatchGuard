#include "crc_f.h"
#include <windows.h>
#include <stdint.h>

static pe_crc_info_t crc_info;
static CRITICAL_SECTION crc_critical_section;
static volatile int monitoring_active = 1;

static void generate_crc32_table(uint32_t *table) {
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t crc = 1;
    for (int j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ CRC32_POLYNOMIAL;
      } else {
        crc = crc >> 1;
      }
    }
    table[i] = crc;
  }
}

uint32_t calculate_pe_crc(uint8_t *base_address, size_t image_size) {
  static uint32_t table[256];
  static int table_generated = 0;
  
  if (!table_generated) {
    generate_crc32_table(table);
    table_generated = 1;
  }

  uint32_t crc = 0xFFFFFFFF;

  IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)base_address;
  IMAGE_DOS_HEADER *nt_headers = (IMAGE_DOS_HEADER*)(base_address + dos_header->e_lfanew);
  
  uint8_t *start_address = base_address + nt_headers->OptionalHeader.SizeOfHeaders;
  size_t data_size = image_size - nt_headers->OptionalHeader.SizeOfHeaders;

  for (size_t i = 0; i < data_size; i++) {
    uint8_t byte = start_address[i];
    uint8_t index = (crc ^ byte) & 0xFF;
    crc = (crc >> 8) ^ table[index];
  }

  return crc ^ 0xFFFFFFFF;
}

static int get_module_info(HMODULE module, uint8_t **base_address, size_t *image_size) {
  MODULEINFO module_info;

  if (!GetModuleInformation(GetCurrentProccess(), module, &module_info, sizeof(module_info))) {
    return 0;
  }

  *base_address = (*uint8_t)module_info.LpBaseOfDll;
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
    
    printf("PE CRC Protection Initialized:\n");
    printf("Base Address: 0x%p\n", crc_info.image_base);
    printf("Image Size: %zu bytes\n", crc_info.image_size);
    printf("Original CRC: 0x%08X\n", crc_info.original_crc);
    
    HANDLE thread = CreateThread(NULL, 0, pe_crc_monitor_thread, NULL, 0, NULL);
    if (!thread) {
        return 0;
    }
    
    CloseHandle(thread);
    return 1;
}

DWORD WINAPI pe_crc_monitor_thread(LPVOID lpParam) {
    printf("CRC Monitoring Thread Started\n");
    
    while (monitoring_active) {
        Sleep(CHECK_INTERVAL_MS);
        
        EnterCriticalSection(&crc_critical_section);
        
        uint8_t* current_base;
        size_t current_size;
        if (get_module_info(crc_info.module_handle, &current_base, &current_size)) {

            if (current_base != crc_info.image_base || current_size != crc_info.image_size) {
                printf("PE image relocated or resized! Integrity violation!\n");
                pe_crc_integrity_violation();
            } else {

                uint32_t current_crc = calculate_pe_crc(crc_info.image_base, crc_info.image_size);
                if (current_crc != crc_info.original_crc) {
                    printf("CRC Mismatch! Original: 0x%08X, Current: 0x%08X\n", 
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


