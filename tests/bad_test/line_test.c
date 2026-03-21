#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_input(const char *user_input)
{
    char buffer[16];

    printf("Processing input...\n");

    // SAFE OPERATION
    memset(buffer, 0, sizeof(buffer));

    // ---------------------------
    // VULNERABLE LINE (overflow)
    // ---------------------------
    strcpy(buffer, user_input);   // <-- expected vulnerable line

    printf("Buffer contains: %s\n", buffer);
}

void helper_function()
{
    int x = 10;
    int y = 20;

    printf("Helper function: %d\n", x + y);
}

int main()
{
    char input[128];

    printf("Enter some text: ");
    scanf("%127s", input);

    process_input(input);

    helper_function();

    return 0;
}
