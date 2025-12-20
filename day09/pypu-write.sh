# File containining the Python bytecode
FILE="p.bin"
BASE_ADDR=0xfebd5100 # BAR0 + 0x100

# Convert p.bin to a list of hex bytes and write them one by one
i=0
for byte in $(od -An -t x1 -v "$FILE"); do
    # Use devmem in 8-bit mode
    devmem $((BASE_ADDR + i)) 8 "0x$byte"
    i=$((i + 1))
done