#include <Windows.h>
#include <string>
#include "pattern_scanner.h"

void disable_dha() {
    DWORD address = pattern_scan(
        "\x53\x56\x57\x83\xc4\x00\x8b\xf2\x8b\xf8",
        "xxxxx?xxxx"
    );

    if (address == 0) {
        MessageBoxA(NULL, "Address not found", "DHA Disabler", MB_ICONERROR);
        return;
    }

    DWORD old_protect;
    VirtualProtect(reinterpret_cast<LPVOID>(address), 1, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(reinterpret_cast<void*>(address), "\xC3", 1);
    VirtualProtect(reinterpret_cast<LPVOID>(address), 1, old_protect, &old_protect);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        disable_dha();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


