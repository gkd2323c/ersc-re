#include <windows.h>
#include <stdio.h>

int main() {
    printf("Loading ersc.dll...\n");
    HMODULE h = LoadLibraryW(L"ersc.dll");
    if (!h) {
        printf("Failed to load: %lu\n", GetLastError());
        return 1;
    }
    printf("Loaded at: %p\n", h);
    
    // Call modengine_ext_init
    typedef void (*InitFunc)(void*);
    InitFunc init = (InitFunc)GetProcAddress(h, "modengine_ext_init");
    if (init) {
        printf("Calling modengine_ext_init...\n");
        // We need a valid arg - just try with null
        init(NULL);
        printf("modengine_ext_init returned\n");
    } else {
        printf("modengine_ext_init not found\n");
    }
    
    printf("Done. Press enter to exit.\n");
    getchar();
    return 0;
}
