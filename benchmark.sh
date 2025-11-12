#!/bin/bash

# Performance comparison script for Shadowrocket rules build process
# This script compares the original and optimized implementations

set -e

echo "=== Shadowrocket Rules Build Performance Comparison ==="
echo "Date: $(date)"
echo "System: $(uname -a)"
echo "Go Version: $(go version)"
echo ""

# Create output directories
mkdir -p benchmark/{original,optimized}

# Function to run build and measure performance
run_benchmark() {
    local implementation=$1
    local binary=$2
    local output_dir=$3
    
    echo "Running $implementation benchmark..."
    
    # Clean previous outputs
    rm -rf cache/* output/*
    
    # Build the binary
    echo "Building $implementation..."
    start_build=$(date +%s)
    
    if [ "$implementation" = "original" ]; then
        go build -o "$binary" ./cmd/merge
    else
        go build -o "$binary" ./cmd/merge/main_optimized.go
    fi
    
    end_build=$(date +%s)
    build_time=$((end_build - start_build))
    
    echo "Build time: ${build_time}s"
    
    # Run the build
    echo "Running $implementation build..."
    start_run=$(date +%s)
    
    if timeout 300 "$binary"; then
        end_run=$(date +%s)
        run_time=$((end_run - start_run))
        
        echo "$implementation completed in ${run_time}s"
        
        # Collect metrics
        domains_count=$(wc -l < output/domains.txt 2>/dev/null || echo "0")
        conf_size=$(stat -f%z output/shadowrocket.conf 2>/dev/null || stat -c%s output/shadowrocket.conf 2>/dev/null || echo "0")
        
        echo "Domains: $domains_count"
        echo "Config size: $conf_size bytes"
        
        # Save results
        cat > "benchmark/${implementation}_results.txt" << EOF
Implementation: $implementation
Build time: ${build_time}s
Run time: ${run_time}s
Total time: $((build_time + run_time))s
Domains: $domains_count
Config size: $conf_size bytes
Success: true
EOF
        
        return 0
    else
        echo "$implementation failed or timed out"
        echo "Implementation: $implementation" > "benchmark/${implementation}_results.txt"
        echo "Success: false" >> "benchmark/${implementation}_results.txt"
        return 1
    fi
}

# Run original benchmark
echo "=== Original Implementation ==="
if run_benchmark "original" "./benchmark/original/merge" "benchmark/original"; then
    original_success=true
else
    original_success=false
fi

echo ""

# Run optimized benchmark
echo "=== Optimized Implementation ==="
if run_benchmark "optimized" "./benchmark/optimized/merge" "benchmark/optimized"; then
    optimized_success=true
else
    optimized_success=false
fi

echo ""

# Compare results
echo "=== Performance Comparison ==="
echo ""

if [ "$original_success" = true ] && [ "$optimized_success" = true ]; then
    # Extract metrics
    original_build=$(grep "Build time:" benchmark/original_results.txt | cut -d' ' -f3 | tr -d 's')
    original_run=$(grep "Run time:" benchmark/original_results.txt | cut -d' ' -f3 | tr -d 's')
    original_total=$(grep "Total time:" benchmark/original_results.txt | cut -d' ' -f3 | tr -d 's')
    original_domains=$(grep "Domains:" benchmark/original_results.txt | cut -d' ' -f2)
    
    optimized_build=$(grep "Build time:" benchmark/optimized_results.txt | cut -d' ' -f3 | tr -d 's')
    optimized_run=$(grep "Run time:" benchmark/optimized_results.txt | cut -d' ' -f3 | tr -d 's')
    optimized_total=$(grep "Total time:" benchmark/optimized_results.txt | cut -d' ' -f3 | tr -d 's')
    optimized_domains=$(grep "Domains:" benchmark/optimized_results.txt | cut -d' ' -f2)
    
    # Calculate improvements
    build_improvement=$(echo "scale=1; ($original_build - $optimized_build) / $original_build * 100" | bc -l)
    run_improvement=$(echo "scale=1; ($original_run - $optimized_run) / $original_run * 100" | bc -l)
    total_improvement=$(echo "scale=1; ($original_total - $optimized_total) / $original_total * 100" | bc -l)
    
    echo "Build Time:"
    echo "  Original:  ${original_build}s"
    echo "  Optimized: ${optimized_build}s"
    echo "  Improvement: ${build_improvement}%"
    echo ""
    
    echo "Run Time:"
    echo "  Original:  ${original_run}s"
    echo "  Optimized: ${optimized_run}s"
    echo "  Improvement: ${run_improvement}%"
    echo ""
    
    echo "Total Time:"
    echo "  Original:  ${original_total}s"
    echo "  Optimized: ${optimized_total}s"
    echo "  Improvement: ${total_improvement}%"
    echo ""
    
    echo "Domains Processed:"
    echo "  Original:  $original_domains"
    echo "  Optimized: $optimized_domains"
    echo ""
    
    # Generate summary report
    cat > benchmark/comparison_report.txt << EOF
Shadowrocket Rules Build Performance Comparison
===============================================
Date: $(date)
System: $(uname -a)
Go Version: $(go version)

Results:
--------
Original Implementation:
  Build Time: ${original_build}s
  Run Time: ${original_run}s
  Total Time: ${original_total}s
  Domains: $original_domains

Optimized Implementation:
  Build Time: ${optimized_build}s
  Run Time: ${optimized_run}s
  Total Time: ${optimized_total}s
  Domains: $optimized_domains

Performance Improvements:
-------------------------
Build Time: ${build_improvement}%
Run Time: ${run_improvement}%
Total Time: ${total_improvement}%

Key Optimizations Applied:
- Parallel network requests with connection pooling
- Batch DNS validation with optimized worker pools
- Enhanced caching mechanisms
- Improved error handling and retry logic
- Memory usage optimization
- Concurrent processing of independent tasks
EOF
    
    echo "Comparison report saved to: benchmark/comparison_report.txt"
else
    echo "Cannot perform comparison - one or both implementations failed"
fi

# Clean up
rm -rf cache/* output/*

echo ""
echo "Benchmark completed. Results saved in benchmark/ directory."