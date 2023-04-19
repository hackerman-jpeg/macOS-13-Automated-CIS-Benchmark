#!/bin/bash

# Helper Functions for macOS CIS Benchmarks Automation

# Initialize counters for passed and failed checks
PASSED=0
FAILED=0

# Pass function
pass() {
  local check_id="$1"
  local title="$2"
  echo "[PASS] $check_id - $title"
  PASSED=$((PASSED+1))
}

# Fail function
fail() {
  local check_id="$1"
  local title="$2"
  echo "[FAIL] $check_id - $title"
  FAILED=$((FAILED+1))
}

# Print summary function
print_summary() {
  echo ""
  echo "Summary:"
  echo "========="
  echo "Passed: $PASSED"
  echo "Failed: $FAILED"
}
