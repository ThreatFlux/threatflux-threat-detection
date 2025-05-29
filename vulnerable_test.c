#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Buffer overflow vulnerability - strcpy without bounds checking
void unsafe_strcpy(char *input) {
    char buffer[100];
    strcpy(buffer, input);  // Dangerous! No bounds checking
    printf("Buffer contents: %s\n", buffer);
}

// Format string vulnerability
void unsafe_printf(char *user_input) {
    printf(user_input);  // Dangerous! User-controlled format string
}

// Use after free vulnerability pattern
void use_after_free_example() {
    char *ptr = malloc(100);
    strcpy(ptr, "test data");
    free(ptr);
    // Dangerous! Using pointer after free
    printf("Freed data: %s\n", ptr);
}

// Division by zero
int unsafe_division(int a, int b) {
    return a / b;  // No check for b == 0
}

// Unbounded sprintf - buffer overflow
void unsafe_sprintf() {
    char buffer[50];
    char large_string[200];
    memset(large_string, 'A', 199);
    large_string[199] = '\0';
    
    sprintf(buffer, "%s", large_string);  // Buffer overflow!
    printf("Result: %s\n", buffer);
}

// Double free vulnerability
void double_free_example() {
    char *ptr = malloc(100);
    strcpy(ptr, "data");
    free(ptr);
    free(ptr);  // Double free!
}

int main() {
    char input[] = "safe input";
    char format[] = "Hello %s\n";
    
    unsafe_strcpy(input);
    unsafe_printf(format);
    use_after_free_example();
    
    int result = unsafe_division(10, 0);  // Division by zero
    printf("Result: %d\n", result);
    
    unsafe_sprintf();
    double_free_example();
    
    return 0;
}