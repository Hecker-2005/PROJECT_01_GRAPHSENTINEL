import os
import random

OUT_DIR = "./data/safe_utils"
os.makedirs(OUT_DIR, exist_ok=True)

# Templates for simple safe functions
templates = [
# Arithmetic
"""
#include <stdio.h>
int add_{n}(int a, int b) {{ return a + b; }}
int sub_{n}(int a, int b) {{ return a - b; }}
int mul_{n}(int a, int b) {{ return a * b; }}
int main() {{
    printf("%d\\n", add_{n}(1, 2));
    printf("%d\\n", sub_{n}(5, 3));
    printf("%d\\n", mul_{n}(4, 6));
    return 0;
}}
""",
# Safe string handling
"""
#include <stdio.h>
#include <string.h>
#define BUF {buf}
void print_msg_{n}(const char *msg) {{
    char buf[BUF];
    strncpy(buf, msg, BUF - 1);
    buf[BUF - 1] = '\\0';
    printf("%s\\n", buf);
}}
int main() {{
    print_msg_{n}("hello");
    return 0;
}}
""",
# Simple conditionals
"""
#include <stdio.h>
int max_{n}(int a, int b) {{ return a > b ? a : b; }}
int min_{n}(int a, int b) {{ return a < b ? a : b; }}
int clamp_{n}(int v, int lo, int hi) {{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}}
int main() {{
    printf("%d\\n", max_{n}(3, 7));
    printf("%d\\n", min_{n}(3, 7));
    printf("%d\\n", clamp_{n}(5, 1, 10));
    return 0;
}}
""",
# Safe array operations
"""
#include <stdio.h>
#define SIZE {size}
void fill_{n}(int arr[], int val) {{
    for (int i = 0; i < SIZE; i++) arr[i] = val;
}}
void print_arr_{n}(int arr[]) {{
    for (int i = 0; i < SIZE; i++) printf("%d ", arr[i]);
    printf("\\n");
}}
int sum_{n}(int arr[]) {{
    int s = 0;
    for (int i = 0; i < SIZE; i++) s += arr[i];
    return s;
}}
int main() {{
    int arr[SIZE];
    fill_{n}(arr, 42);
    print_arr_{n}(arr);
    printf("sum=%d\\n", sum_{n}(arr));
    return 0;
}}
""",
# Safe struct usage
"""
#include <stdio.h>
#include <string.h>
typedef struct {{
    int x;
    int y;
}} Point_{n};
Point_{n} make_point_{n}(int x, int y) {{
    Point_{n} p;
    p.x = x; p.y = y;
    return p;
}}
void print_point_{n}(Point_{n} p) {{
    printf("(%d, %d)\\n", p.x, p.y);
}}
int main() {{
    Point_{n} p = make_point_{n}(3, 4);
    print_point_{n}(p);
    return 0;
}}
""",
]

count = 0
for i in range(200):
    tmpl = random.choice(templates)
    buf  = random.choice([32, 64, 128, 256])
    size = random.choice([4, 8, 16, 32])
    code = tmpl.format(n=i, buf=buf, size=size)
    path = os.path.join(OUT_DIR, f"safe_util_{i:03d}.c")
    with open(path, "w") as f:
        f.write(code)
    count += 1

print(f"Generated {count} safe utility files in {OUT_DIR}")
