#!/bin/bash

# Fix Zod v4 breaking changes across all TypeScript files

echo "Fixing Zod v4 breaking changes..."

# Find all TypeScript files in src directory
find src -name "*.ts" | while read file; do
    echo "Processing $file..."
    
    # Fix z.record() patterns - add explicit key types
    # Fix z.record(z.string()) to z.record(z.string(), z.string())
    sed -i '' 's/z\.record(z\.string())/z.record(z.string(), z.string())/g' "$file"
    
    # Fix z.record(z.any()) to z.record(z.string(), z.any())
    sed -i '' 's/z\.record(z\.any())/z.record(z.string(), z.any())/g' "$file"
    
    # Fix z.record(z.unknown()) to z.record(z.string(), z.unknown())
    sed -i '' 's/z\.record(z\.unknown())/z.record(z.string(), z.unknown())/g' "$file"
    
    # Fix z.record(z.number().min(1)) to z.record(z.string(), z.number().min(1))
    sed -i '' 's/z\.record(z\.number()\.min(1))/z.record(z.string(), z.number().min(1))/g' "$file"
    
    # Fix z.record(z.array(z.string())) to z.record(z.string(), z.array(z.string()))
    sed -i '' 's/z\.record(z\.array(z\.string()))/z.record(z.string(), z.array(z.string()))/g' "$file"
    
    # Fix z.record(z.number()) to z.record(z.string(), z.number())
    sed -i '' 's/z\.record(z\.number())/z.record(z.string(), z.number())/g' "$file"
    
    echo "Fixed z.record() patterns in $file"
done

echo "All files processed!"