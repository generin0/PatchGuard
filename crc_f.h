#ifndef CRC_F_H
#define CRC_F_H

#include <stdint.h>
#include <windows.h>

#define CRC_INTERVAL_MS 5000
#define CRC_POLYNOMIAL 0xEDB88320

typedef struct {
  uint32_t original_crc;
  HMODULE module_handle;
  size_t image_size;
  uint8_t *image_base;
} pe_crc_info_t;

int pe_crc_init(void);

DWORD WINAPI pe_crc_monitor_thread(LPVOID lpParam);

uint32_t calculate_pe_crc(uint8_t *base_address, size_t image_size);

void pe_crc_integrity_violation(void);

#endif
