#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer = malloc(8);

    // Write far beyond allocated memory
    strcpy(buffer, "THIS_IS_A_VERY_LONG_STRING");

    printf("%s\n", buffer);
    free(buffer);
    return 0;
}
