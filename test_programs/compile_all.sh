#!/bin/bash

# Compilation script for all test programs
# Run this script after installing the required compilers

echo "=== Compiling Test Programs ==="
echo "Note: This script requires various compilers to be installed"
echo ""

# Pascal (requires fpc - Free Pascal Compiler)
if command -v fpc &> /dev/null; then
    echo "Compiling Pascal test..."
    fpc -O2 pascal_test.pas -opascal_test_binary
else
    echo "Warning: fpc (Free Pascal Compiler) not found - skipping Pascal"
fi

# Nim (requires nim compiler)
if command -v nim &> /dev/null; then
    echo "Compiling Nim test..."
    nim c -d:release --opt:speed -o:nim_test_binary nim_test.nim
else
    echo "Warning: nim compiler not found - skipping Nim"
fi

# D Language (requires dmd, gdc, or ldc)
if command -v dmd &> /dev/null; then
    echo "Compiling D test with dmd..."
    dmd -O -release -of=d_test_binary d_test.d
elif command -v gdc &> /dev/null; then
    echo "Compiling D test with gdc..."
    gdc -O2 -frelease -o d_test_binary d_test.d
elif command -v ldc2 &> /dev/null; then
    echo "Compiling D test with ldc2..."
    ldc2 -O3 -release -of=d_test_binary d_test.d
else
    echo "Warning: No D compiler (dmd/gdc/ldc2) found - skipping D"
fi

# Fortran (requires gfortran)
if command -v gfortran &> /dev/null; then
    echo "Compiling Fortran test..."
    gfortran -O2 fortran_test.f90 -o fortran_test_binary
else
    echo "Warning: gfortran not found - skipping Fortran"
fi

# Ada (requires gnatmake)
if command -v gnatmake &> /dev/null; then
    echo "Compiling Ada test..."
    gnatmake -O2 ada_test.adb -o ada_test_binary
else
    echo "Warning: gnatmake (GNAT Ada compiler) not found - skipping Ada"
fi

echo ""
echo "=== Compilation Summary ==="
echo "Compiled binaries:"
ls -la *_binary 2>/dev/null || echo "No binaries compiled (missing compilers)"

echo ""
echo "To install missing compilers on Ubuntu/Debian:"
echo "  sudo apt-get install fpc           # Pascal"
echo "  curl https://nim-lang.org/choosenim/init.sh -sSf | sh  # Nim"
echo "  sudo apt-get install dmd-compiler  # D Language"
echo "  sudo apt-get install gfortran      # Fortran"
echo "  sudo apt-get install gnat          # Ada"