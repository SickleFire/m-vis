#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define SLEEP_SEC(n) Sleep((n) * 1000)
#else
#include <unistd.h>
#define SLEEP_SEC(n) sleep(n)
#endif

void* leak_registry[1000];

int main() {
    int i = 0;
    while (i < 1000) {
        void* ptr = malloc(1024 * 1024);
        if (ptr != NULL) {
            memset(ptr, 0xAB, 1024 * 1024);
            leak_registry[i] = ptr;
            i++;
        }
        SLEEP_SEC(1);
    }
    return 0;
}