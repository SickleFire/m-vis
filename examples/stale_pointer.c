#include <stdio.h>
#include <stdlib.h>

static void * volatile *g_holder;

int main(void) {
    void *victim = malloc(64);
    g_holder = (void * volatile *)malloc(sizeof(*g_holder));

    if (victim == NULL || g_holder == NULL) {
        fprintf(stderr, "allocation failed\n");
        free(victim);
        free((void *)g_holder);
        return 1;
    }

    *g_holder = victim;
    printf("Process is ready for inspection.\n");
    printf("Holder address: %p\n", (void *)g_holder);
    printf("Freed target:   %p\n", victim);
    printf("The holder still contains the freed target address.\n");
    printf("Do not dereference the stale pointer. Press Enter to exit.\n");
    fflush(stdout);

    free(victim);

    (void)getchar();

    free((void *)g_holder);
    g_holder = NULL;
    return 0;
}
