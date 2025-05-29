#include <stdio.h>
#include <stdlib.h>

void helper_func() {
    printf("Helper function\n");
}

void recursive_func(int n) {
    if (n > 0) {
        printf("Count: %d\n", n);
        recursive_func(n - 1);  // Recursive call
    }
}

void indirect_caller(void (*func)()) {
    func();  // Indirect call
}

void unreachable_func() {
    printf("This function is never called\n");
}

int main() {
    printf("Main function\n");
    helper_func();  // Direct call
    recursive_func(5);  // Direct call to recursive function
    indirect_caller(helper_func);  // Pass function pointer
    
    // Function pointer
    void (*ptr)() = helper_func;
    ptr();  // Indirect call through pointer
    
    return 0;
}