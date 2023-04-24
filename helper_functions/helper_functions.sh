#!/bin/bash

# Helper Functions for macOS CIS Benchmarks Automation
#UNDER DEV, please note this may be broken
 
# Initialize counters for passed and failed checks
PASSED=0
FAILED=0

# Pass function for a check that passes
pass() {
  local check_id="$1"
  local title="$2"
  echo "[PASS] $check_id - $title"
  PASSED=$((PASSED+1))
}

# Fail function for a check that fails
fail() {
  local check_id="$1"
  local title="$2"
  echo "[FAIL] $check_id - $title"
  FAILED=$((FAILED+1))
}

# Print summary function for total findings
print_summary() {
  echo ""
  echo "Summary:"
  echo "========="
  echo "Passed: $PASSED"
  echo "Failed: $FAILED"
}
