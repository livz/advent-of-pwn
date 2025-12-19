import re
import sys

code_fname = "2025~day-01.code" 
output_fname = "reconstructed_key.bin"

# Store operations by variable name: {'var_400': [(address, op, val), ...], ...}
variable_ops = {}

# --- Helper Function for Inverse Arithmetic ---
def invert_op(current_value, operation, value_hex):
    """Performs the inverse operation modulo 256."""
    
    val = 0
    try:
        # 1. Convert hex value to integer, handling 'h' suffix
        if value_hex.endswith('h'):
            val = int(value_hex[:-1], 16)
        else:
            val = int(value_hex, 16) 
    except ValueError:
        sys.exit(f"Critical Error: Invalid hex value '{value_hex}' found during operation '{operation}'. Halting.") 

    # 2. Apply inverse operation (all arithmetic is modulo 256 for a byte)
    if operation == 'add':
        return (current_value - val) % 256
    elif operation == 'sub':
        return (current_value + val) % 256
    else:
        return current_value

with open(code_fname, "r") as f:
    listing = f.read()

# Group 1: Address, Group 2: Operation, Group 3: Variable, Group 4: Value
pattern = re.compile(r'\.text:([0-9A-Fa-f]+).*?(add|sub|cmp)\s+\[\w+\+(var_\w+)\],\s*(\w+)')

for line in listing.split("\n"):
    match = pattern.search(line)
    
    if match:
        address_hex = match.group(1)
        operation = match.group(2)
        variable = match.group(3)
        value_hex = match.group(4)
        
        op_data = (int(address_hex, 16), operation, value_hex)
        
        if variable not in variable_ops:
            variable_ops[variable] = []
        
        variable_ops[variable].append(op_data)

# Sort variables by the numerical value of their hex index, in descending order
sorted_variables = sorted(variable_ops.keys(), 
                          key=lambda x: int(x.split('_')[1], 16), 
                          reverse=True)

reconstructed_bytes = []
for variable in sorted_variables:
    ops = variable_ops[variable]
    
    # Sort operations by address to get correct execution order
    ops.sort(key=lambda x: x[0])
    
    # The last operation MUST be the final comparison (cmp)
    final_op = ops[-1]
    
    if final_op[1] != 'cmp':
        sys.exit(f"Critical Error: Last operation for {variable} is '{final_op[1]}', not 'cmp'. Halting.")

    # Start with the expected final value from the CMP instruction
    try:
        final_value = int(final_op[2].replace('h', ''), 16)
    except ValueError:
        sys.exit(f"Critical Error: Invalid final comparison value '{final_op[2]}' for {variable}. Halting.")

    current_byte_value = final_value
    
    # Iterate backward through the operations (excluding the final 'cmp')
    for op_address, operation, value_hex in reversed(ops[:-1]):
        current_byte_value = invert_op(current_byte_value, operation, value_hex)
        
    reconstructed_bytes.append(current_byte_value)

final_key_bytes = bytes(reconstructed_bytes)

print("--- Key Reconstruction Complete ---")
print(f"Key length: {len(final_key_bytes)} bytes")

with open(output_fname, 'wb') as f:
    f.write(final_key_bytes)
print(f"\nSuccessfully wrote the reconstructed key to '{output_fname}' (binary format).")
