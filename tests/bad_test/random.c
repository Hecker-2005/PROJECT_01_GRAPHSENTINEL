#include <stdlib.h>
#include <string.h>

int main() {
    char *p = malloc(4);

    strcpy(p, "AAAAAAAAAAAAAAAAAAAA"); // overflow
    free(p);
    p[0] = 'B'; // use after free

    return 0;
}
