#!/bin/bash

# macOS CIS Benchmarks Automation - Main Script
# This script automates the CIS benchmarks checks for macOS 13 Ventura.
# It sources the required helper functions and check scripts, then runs the checks.

# Source the helper functions
source "./helper_functions/helper_functions.sh"

# Source the check scripts
# Replace the paths with the correct ones if I change
source "./checks/check_1_1.sh"
source "./checks/check_1_2.sh"
source "./checks/check_1_3.sh"
source "./checks/check_1_4.sh"
source "./checks/check_1_5.sh"
source "./checks/check_1_6.sh"
source "./checks/check_1_7.sh"

# Add more source lines for additional check scripts as needed

# Run the checks

# I need to add a line for each check function that needs to be called possibly
check_1_1
check_1_2
check_1_3
check_1_4
check_1_5
check_1_6
check_1_7

# Add more check function calls for additional checks as needed

# Print the summary of the check results
print_summary
