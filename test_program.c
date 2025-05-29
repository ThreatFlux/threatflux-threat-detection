#include <stdio.h>

// Simple function with basic blocks
int add_numbers(int a, int b) {
    return a + b;
}

// Function with conditional
int max_number(int a, int b) {
    if (a > b) {
        return a;
    } else {
        return b;
    }
}

// Function with loop
int factorial(int n) {
    int result = 1;
    for (int i = 1; i <= n; i++) {
        result *= i;
    }
    return result;
}

// Function with nested conditionals and loops
int complex_function(int x) {
    int result = 0;
    
    if (x > 10) {
        for (int i = 0; i < x; i++) {
            if (i % 2 == 0) {
                result += i;
            } else {
                result -= i;
            }
        }
    } else if (x > 5) {
        while (x > 0) {
            result += x;
            x--;
        }
    } else {
        result = x * 2;
    }
    
    return result;
}

int main() {
    int a = 5, b = 10;
    
    printf("Add: %d\n", add_numbers(a, b));
    printf("Max: %d\n", max_number(a, b));
    printf("Factorial: %d\n", factorial(a));
    printf("Complex: %d\n", complex_function(a));
    
    return 0;
}