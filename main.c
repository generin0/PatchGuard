#include "crc_f.h"
#include <stdio.h>

void demo_func(void) {
  printf("[+] Demo func executed.");
}

int main(void) {
  printf("[+] Starting application with PatchCRC protection.");

  if (!pe_crc_init()) {
    printf("[-] Failed to initialize PatchCRC."]);
    return 1;
  }

  for (int i = 0; i < 10; i++) {
    printf("[+] Application is running...");
    demo_func();
    Sleep(1000);

    if (i == 5) {
      printf("[+] Attempting to modify code...");
      
      uint8_t *func_addr = (uint8_t*)demo_func;
      func_addr[0] = 0xC3;
    }
  }

  pe_crc_stop();
  printf("Application finished.\n");
  return 0;
}
