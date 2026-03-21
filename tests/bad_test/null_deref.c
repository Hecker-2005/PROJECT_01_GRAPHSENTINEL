#include <stdio.h>
#include <stdlib.h>

int main() {
    char *ptr = NULL;

    // Immediate null dereference
    ptr[0] = 'A';

    printf("Done\n");
    return 0;
}
