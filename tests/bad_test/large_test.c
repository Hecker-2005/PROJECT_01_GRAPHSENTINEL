#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ═══════════════════════════════════════════════════════════
// SAFE FUNCTIONS (should score low / not flagged)
// ═══════════════════════════════════════════════════════════

// F01 - SAFE: pure arithmetic
int add(int a, int b) {
    return a + b;
}

// F02 - SAFE: safe string length check
int safe_strlen(const char *s) {
    if (s == NULL) return 0;
    return (int)strlen(s);
}

// F03 - SAFE: bounded copy
void safe_copy(char *dst, const char *src, size_t max) {
    if (!dst || !src || max == 0) return;
    strncpy(dst, src, max - 1);
    dst[max - 1] = '\0';
}

// F04 - SAFE: proper null check before deref
int safe_deref(int *ptr) {
    if (ptr == NULL) return -1;
    return *ptr;
}

// F05 - SAFE: proper malloc + check
char *safe_alloc(size_t size) {
    if (size == 0) return NULL;
    char *buf = malloc(size);
    if (buf == NULL) return NULL;
    memset(buf, 0, size);
    return buf;
}

// F06 - SAFE: proper free with null guard
void safe_free(char **ptr) {
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = NULL;
    }
}

// F07 - SAFE: bounded array access
int safe_array_get(int *arr, int len, int idx) {
    if (!arr || idx < 0 || idx >= len) return -1;
    return arr[idx];
}

// F08 - SAFE: correct printf format
void safe_log(const char *tag, const char *msg) {
    if (!tag || !msg) return;
    printf("[%s] %s\n", tag, msg);
}

// F09 - SAFE: proper loop with bounds
int sum_array(int *arr, int len) {
    if (!arr || len <= 0) return 0;
    int total = 0;
    for (int i = 0; i < len; i++)
        total += arr[i];
    return total;
}

// F10 - SAFE: correct division with zero check
float safe_divide(float a, float b) {
    if (b == 0.0f) return 0.0f;
    return a / b;
}

// F11 - SAFE: proper resource cleanup
FILE *safe_open(const char *path, const char *mode) {
    if (!path || !mode) return NULL;
    return fopen(path, mode);
}

// F12 - SAFE: recursive with base case
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// ═══════════════════════════════════════════════════════════
// PARTIALLY VULNERABLE (minor issues, borderline)
// ═══════════════════════════════════════════════════════════

// F13 - PARTIAL: no null check on input but bounded copy
void partial_copy(char *dst, const char *src) {
    strncpy(dst, src, 63);
    dst[63] = '\0';
}

// F14 - PARTIAL: malloc without checking return
char *partial_alloc(int size) {
    char *buf = malloc(size);
    memset(buf, 0, size);   // potential null deref if malloc fails
    return buf;
}

// F15 - PARTIAL: missing break in switch — fallthrough
int partial_switch(int code) {
    int result = 0;
    switch (code) {
        case 1: result = 10;
        case 2: result = 20;    // fallthrough from case 1
        case 3: result = 30;    // fallthrough from case 2
            break;
        default: result = -1;
    }
    return result;
}

// F16 - PARTIAL: signed/unsigned comparison warning-prone
int partial_compare(int len, char *buf) {
    unsigned int ulen = strlen(buf);
    if (len < ulen) {   // signed/unsigned mismatch
        return -1;
    }
    return 0;
}

// F17 - PARTIAL: reading uninitialized variable in some paths
int partial_uninit(int flag) {
    int result;
    if (flag > 0) {
        result = flag * 2;
    }
    return result;  // uninitialized if flag <= 0
}

// F18 - PARTIAL: resource leak on error path
int partial_resource_leak(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[64];
    if (!fgets(buf, sizeof(buf), f)) {
        return -2;  // file handle leaked
    }
    fclose(f);
    return 0;
}

// F19 - PARTIAL: integer truncation
short partial_truncation(int val) {
    return (short)val;  // silently truncates if val > 32767
}

// F20 - PARTIAL: unchecked return from sscanf
int partial_parse(const char *input, int *out) {
    sscanf(input, "%d", out);  // no return value check
    return *out;
}

// ═══════════════════════════════════════════════════════════
// VULNERABLE (clear exploitable issues)
// ═══════════════════════════════════════════════════════════

// F21 - VULNERABLE: classic stack overflow
void vuln_stack_overflow(const char *input) {
    char buffer[32];
    strcpy(buffer, input);  // no bounds check
    printf("Got: %s\n", buffer);
}

// F22 - VULNERABLE: heap overflow
void vuln_heap_overflow(const char *data) {
    char *buf = malloc(16);
    strcpy(buf, data);  // overflows if data > 15 chars
    free(buf);
}

// F23 - VULNERABLE: format string
void vuln_format_string(const char *user_input) {
    printf(user_input);  // direct format string injection
}

// F24 - VULNERABLE: null dereference without check
int vuln_null_deref(int *ptr) {
    return *ptr + 1;  // no null check
}

// F25 - VULNERABLE: integer overflow to buffer overflow
char *vuln_int_overflow(int user_size) {
    int total = user_size + 128;    // overflows if user_size near INT_MAX
    char *buf = malloc(total);
    return buf;
}

// F26 - VULNERABLE: out-of-bounds array write
void vuln_oob_write(int *arr, int idx, int val) {
    arr[idx] = val;     // no bounds check
}

// F27 - VULNERABLE: use of gets (inherently dangerous)
void vuln_gets(void) {
    char buf[64];
    gets(buf);          // gets() has no bounds — always vulnerable
    printf("%s\n", buf);
}

// F28 - VULNERABLE: off-by-one overflow
void vuln_off_by_one(char *dst, const char *src, int size) {
    for (int i = 0; i <= size; i++) {   // should be i < size
        dst[i] = src[i];                // writes one byte past end
    }
}

// ═══════════════════════════════════════════════════════════
// CRITICAL (severe, multi-issue, easy exploit)
// ═══════════════════════════════════════════════════════════

// F29 - CRITICAL: use-after-free
void crit_use_after_free(void) {
    char *buf = malloc(64);
    memset(buf, 'A', 63);
    buf[63] = '\0';
    free(buf);
    printf("Data: %s\n", buf);  // access after free
    buf[0] = 'X';               // write after free
}

// F30 - CRITICAL: double free
void crit_double_free(char *data, int condition) {
    char *buf = malloc(64);
    strncpy(buf, data, 63);
    if (condition) {
        free(buf);
    }
    free(buf);  // always freed — double free when condition is true
}

// F31 - CRITICAL: stack overflow + format string combined
void crit_combined(const char *user_input) {
    char local[16];
    sprintf(local, user_input);     // format string + potential overflow
    printf(local);                  // double format string vuln
}

// F32 - CRITICAL: uncontrolled memory allocation
void crit_uncontrolled_alloc(int user_val) {
    size_t size = (size_t)user_val * 1024 * 1024;  // user controls allocation size
    char *buf = malloc(size);
    if (buf) {
        memset(buf, 0, size);   // can exhaust memory
        free(buf);
    }
}

// F33 - CRITICAL: write-what-where via pointer arithmetic
void crit_write_what_where(char *base, int offset, char val) {
    *(base + offset) = val;     // no bounds, user controls offset and value
}

// F34 - CRITICAL: recursive overflow (unbounded recursion)
int crit_unbounded_recursion(int n) {
    return n + crit_unbounded_recursion(n - 1);  // no base case — stack overflow
}

// ═══════════════════════════════════════════════════════════
// MAIN — safe orchestration
// ═══════════════════════════════════════════════════════════
int main(void) {
    // Safe operations
    printf("add:      %d\n",  add(3, 4));
    printf("factorial:%d\n",  factorial(5));
    printf("divide:   %.2f\n",safe_divide(10.0f, 3.0f));

    int arr[] = {1, 2, 3, 4, 5};
    printf("sum:      %d\n",  sum_array(arr, 5));
    printf("get[2]:   %d\n",  safe_array_get(arr, 5, 2));

    char *mem = safe_alloc(64);
    safe_copy(mem, "hello world", 64);
    safe_log("INFO", mem);
    safe_free(&mem);

    FILE *f = safe_open("/dev/null", "r");
    if (f) fclose(f);

    printf("Done.\n");
    return 0;
}