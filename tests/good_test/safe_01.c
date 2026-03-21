#include <stdio.h>
#include <string.h>

#define MAX_LEN 64

void greet_user(const char *name) {
    char buffer[MAX_LEN];

    // Safe bounded copy
    strncpy(buffer, name, MAX_LEN - 1);
    buffer[MAX_LEN - 1] = '\0';

    printf("Hello, %s!\n", buffer);
}

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

void print_result(int result) {
    printf("Result: %d\n", result);
}

int main() {
    greet_user("Alice");

    int x = add(3, 4);
    int y = multiply(x, 2);

    print_result(y);

    return 0;
}