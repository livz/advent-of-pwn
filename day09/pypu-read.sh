#!/bin/sh

# BAR Addresses
STDOUT_BAR=0xfebd6000
STDERR_BAR=0xfebd7000

read_bar() {
    local base=$1
    local name=$2
    printf "[*] Reading %s\n" "$name"
    
    for i in $(seq 0 255); do
        # Get the hex value (e.g., 0x41)
        val=$(devmem $((base + i)) 8)
        
        # Stop if we hit a null byte (end of string)
        if [ "$val" = "0x00" ]; then
            break
        fi
        
        # Convert hex to octal for printf
        octal_val=$(printf '%o' "$val")
        printf "\\$octal_val"
    done
    printf "\n\n"
}

# Execute reads
read_bar $STDOUT_BAR "STDOUT (BAR 1)"
read_bar $STDERR_BAR "STDERR (BAR 2)"