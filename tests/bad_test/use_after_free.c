#include <stdio.h>
#include <stdlib.h>

int main() {
    int *data = malloc(sizeof(int));
    *data = 42;

    free(data);

    // Use-after-free
    printf("%d\n", *data);

    return 0;
}
