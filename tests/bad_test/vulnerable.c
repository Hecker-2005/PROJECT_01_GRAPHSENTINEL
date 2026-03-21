#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USERS 5
#define BUFFER_SIZE 32

// ─────────────────────────────────────────
// Struct definition
// ─────────────────────────────────────────
typedef struct {
    int id;
    char name[BUFFER_SIZE];
    char *notes;
} User;

// ─────────────────────────────────────────
// VULNERABILITY 1: Stack buffer overflow
// Function: register_user
// Expected line: strcpy with unchecked input
// ─────────────────────────────────────────
void register_user(User *u, int id, const char *name) {
    u->id = id;
    strcpy(u->name, name);  // no bounds check — overflow if name > 31 chars
}

// ─────────────────────────────────────────
// VULNERABILITY 2: Heap overflow
// Function: set_notes
// Expected line: strcpy into fixed heap buffer
// ─────────────────────────────────────────
void set_notes(User *u, const char *notes) {
    u->notes = malloc(16);
    if (u->notes == NULL) return;
    strcpy(u->notes, notes);  // overflow if notes > 15 chars
}

// ─────────────────────────────────────────
// SAFE FUNCTION: print_user
// No vulnerabilities — should score low
// ─────────────────────────────────────────
void print_user(const User *u) {
    printf("ID:    %d\n", u->id);
    printf("Name:  %s\n", u->name);
    if (u->notes != NULL) {
        printf("Notes: %s\n", u->notes);
    }
}

// ─────────────────────────────────────────
// VULNERABILITY 3: Use-after-free
// Function: delete_user
// Expected line: access after free
// ─────────────────────────────────────────
void delete_user(User *u) {
    free(u->notes);
    printf("Deleted notes: %s\n", u->notes);  // use-after-free
    u->notes = NULL;
}

// ─────────────────────────────────────────
// VULNERABILITY 4: Double free
// Function: cleanup_user
// Expected line: second free
// ─────────────────────────────────────────
void cleanup_user(User *u) {
    free(u->notes);
    // ... some logic ...
    free(u->notes);  // double free
}

// ─────────────────────────────────────────
// SAFE FUNCTION: compute_score
// Pure arithmetic — no memory ops
// ─────────────────────────────────────────
int compute_score(int base, int multiplier) {
    if (multiplier <= 0) return 0;
    return base * multiplier;
}

// ─────────────────────────────────────────
// VULNERABILITY 5: NULL dereference
// Function: find_user
// Expected line: dereference without null check
// ─────────────────────────────────────────
User *find_user(User *users[], int count, int id) {
    for (int i = 0; i < count; i++) {
        if (users[i]->id == id) {
            return users[i];
        }
    }
    return NULL;
}

void process_user_by_id(User *users[], int count, int id) {
    User *u = find_user(users, count, id);
    printf("Processing user: %s\n", u->name);  // no null check — null deref
}

// ─────────────────────────────────────────
// VULNERABILITY 6: Format string
// Function: log_input
// Expected line: printf with user input directly
// ─────────────────────────────────────────
void log_input(const char *user_input) {
    printf(user_input);  // format string vulnerability
}

// ─────────────────────────────────────────
// SAFE FUNCTION: safe_log
// Correct format string usage
// ─────────────────────────────────────────
void safe_log(const char *message) {
    printf("%s\n", message);
}

// ─────────────────────────────────────────
// VULNERABILITY 7: Integer overflow leading
// to undersized allocation
// Function: create_buffer
// ─────────────────────────────────────────
char *create_buffer(int size) {
    int total = size + 256;  // can overflow if size is close to INT_MAX
    char *buf = malloc(total);
    return buf;
}

// ─────────────────────────────────────────
// main — orchestration only, should be safe
// ─────────────────────────────────────────
int main() {
    // Setup users
    User *users[MAX_USERS];

    for (int i = 0; i < MAX_USERS; i++) {
        users[i] = malloc(sizeof(User));
        users[i]->notes = NULL;
    }

    // Register with safe input
    register_user(users[0], 1, "Alice");
    register_user(users[1], 2, "Bob");

    // Set notes safely
    set_notes(users[0], "admin");
    set_notes(users[1], "user");

    // Print
    print_user(users[0]);
    print_user(users[1]);

    // Compute score
    int score = compute_score(10, 5);
    printf("Score: %d\n", score);

    // Safe log
    safe_log("System initialized.");

    // Cleanup
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i]->notes != NULL) {
            free(users[i]->notes);
        }
        free(users[i]);
    }

    return 0;
}