#!/bin/bash
# Script to run tests, analyze coverage, and suggest improvements

set -e

# Define thresholds and goals
TARGET_COVERAGE=90
CURRENT_GOAL=80

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

# Display summary
echo ""
echo "==== Coverage Summary ===="
echo "Current total coverage: $TOTAL_COVERAGE%"
echo "Current goal: $CURRENT_GOAL%"
echo "Long-term target: $TARGET_COVERAGE%"

# Check if we've reached our current goal
if (( $(echo "$TOTAL_COVERAGE >= $CURRENT_GOAL" | bc -l) )); then
  echo ""
  echo "🎉 GOAL ACHIEVED: Coverage of $TOTAL_COVERAGE% meets the current goal of $CURRENT_GOAL%!"
  
  # If we've exceeded our current goal but not reached the target, suggest a new goal
  if (( $(echo "$TOTAL_COVERAGE < $TARGET_COVERAGE" | bc -l) )); then
    NEW_GOAL=$(( TOTAL_COVERAGE + 5 ))
    if (( $NEW_GOAL > $TARGET_COVERAGE )); then
      NEW_GOAL=$TARGET_COVERAGE
    fi
    echo "Consider setting a new goal of $NEW_GOAL% in this script."
  else
    echo "Congratulations! You've reached your target coverage of $TARGET_COVERAGE%"
  fi
else
  # Calculate how many more percentage points we need
  NEEDED=$(( CURRENT_GOAL - TOTAL_COVERAGE ))
  echo ""
  echo "We need ${NEEDED}% more coverage to reach the current goal of $CURRENT_GOAL%"
  
  # Get the list of untested or poorly tested functions
  echo ""
  echo "==== Top Functions to Test Next ===="
  echo "$COVERAGE_OUTPUT" | grep -v " 100.0%" | sort -k 3 -n | head -10
fi

# Generate HTML report
go tool cover -html=coverage.filtered.out -o coverage.html
echo ""
echo "Coverage report generated: coverage.html"

# Suggest next steps
echo ""
echo "==== Suggested Next Steps ===="
echo "1. Review 'coverage.html' to identify untested code"
echo "2. Focus on functions with 0.0% coverage first"
echo "3. Write tests for one function at a time"
echo "4. Run this script again to check progress"