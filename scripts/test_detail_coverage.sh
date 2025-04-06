#!/bin/bash
# Script to check test coverage and identify areas needing more tests

set -e

# Define thresholds
COVERAGE_THRESHOLD=70
LOW_COVERAGE_THRESHOLD=50

# Run tests with coverage
echo "Running tests with coverage..."
go test -coverprofile=coverage.raw.out ./auth/...

# Create filtered coverage file
echo "Filtering coverage data..."
cat coverage.raw.out | grep -v "/mock/" | grep -v "/testing/" | grep -v "_test.go" > coverage.filtered.out

# Get coverage totals
echo "Analyzing coverage..."
COVERAGE_OUTPUT=$(go tool cover -func=coverage.filtered.out)
TOTAL_COVERAGE=$(echo "$COVERAGE_OUTPUT" | grep "total:" | awk '{print $3}' | sed 's/%//')
TOTAL_COVERAGE=${TOTAL_COVERAGE%.*} # Remove decimal part

# Display coverage by function
echo "==== Coverage by Function ===="
echo "$COVERAGE_OUTPUT" | sort -k 3 -n

# Check total coverage
echo ""
echo "==== Total Coverage: $TOTAL_COVERAGE% ===="

# Identify functions with low coverage
echo ""
echo "==== Functions Needing More Tests (below $LOW_COVERAGE_THRESHOLD%) ===="
echo "$COVERAGE_OUTPUT" | awk -v threshold=$LOW_COVERAGE_THRESHOLD '{
  if ($3 ~ /%/) {
    coverage = $3;
    gsub(/%/, "", coverage);
    if (coverage < threshold) {
      print $0
    }
  }
}' | sort -k 3 -n

# Check against threshold
if (( $(echo "$TOTAL_COVERAGE < $COVERAGE_THRESHOLD" | bc -l) )); then
  echo ""
  echo "COVERAGE WARNING: Total coverage ($TOTAL_COVERAGE%) is below the threshold ($COVERAGE_THRESHOLD%)"
  echo "Please add more tests to increase coverage."
  exit 1
else
  echo ""
  echo "COVERAGE OK: Total coverage ($TOTAL_COVERAGE%) meets the threshold ($COVERAGE_THRESHOLD%)"
  exit 0
fi