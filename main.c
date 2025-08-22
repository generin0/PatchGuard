#include "crc_f.h"
#include <stdio.h>
#include <windows.h>

void demo_func(void) {
    printf("Demo func executed.\n");
}

int main(void) {
    printf("[+] Starting application with PatchCRC protection.\n");

    if (!pe_crc_init()) {
        printf("[-] Failed to initialize PatchCRC.\n");
        return 1;
    }

    for (int i = 0; i < 10; i++) {
        printf("Application is running... %d\n", i);
        demo_func();
        Sleep(1000);

        if (i == 5) {
            printf("Trying to modify code...\n");

            uint8_t* addr_func = (uint8_t*)demo_func;
            DWORD old_protect;

            if (VirtualProtect(demo_func, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
                addr_func[0] = 0xC3;
                VirtualProtect(demo_func, 1, old_protect, &old_protect);
            }
        }
    }

    pe_crc_stop();
    printf("[+] Application finished.\n");
    return 0;
}
