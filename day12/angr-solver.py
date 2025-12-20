import os
import angr
import logging

# Suppress verbose logging
logging.getLogger('angr').setLevel(logging.ERROR)

BIN_DIR = "/opt/naughty-or-nice"
OUT_DIR = "/home/hacker/my-list"

def find_success_address(bin_path):

    with open(bin_path, 'rb') as f:
        data = f.read()
    
    # Success message length
    # E.g.: 00407cdb   48 c7 c2 31 00 00 00       MOV RDX,0x31                
    pattern = b'\x48\xc7\xc2\x31\x00\x00\x00'
    offset = data.find(pattern)
    base = 0x400000

    if offset != -1:
        addr = base + offset
        print(f"[*] Found success path at {addr:08x}")  
        return addr

    return None

def solve_binary(bin_path):

    success_addr = find_success_address(bin_path)
    if not target_addr:
        sys.exit(1)

    # Load without shared libraries to increase speed
    proj = angr.Project(bin_path, auto_load_libs = False)
    
    # Initialize state with zero-filling to handle large SIMD registers/memory
    state = proj.factory.entry_state(
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
    )
    
    simgr = proj.factory.simulation_manager(state)
    
    # Explore for the dynamically found success path
    simgr.explore(find = success_addr)
    
    if simgr.found:
        return simgr.found[0].posix.dumps(0)
    
    return None

if __name__ == "__main__":

    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)
    
    # Get all binaries and sort them
    binaries = sorted(os.listdir(BIN_DIR))
    total = len(binaries)

    print(f"[*] Starting solver for {total} binaries")

    for i, filename in enumerate(binaries, 1):

        print(f"[{i}/{total}] Solving {filename}...", flush = True)

        # Solution path
        target_path = os.path.join(OUT_DIR, filename)
        
        # Skip files already solved
        if os.path.exists(target_path):
            print("[+] Already solved")
            continue
            
        # Binary to be solved
        full_path = os.path.join(BIN_DIR, filename)
        
        try:
            solution = solve_binary(full_path)
            if solution:
                with open(target_path, "wb") as f:
                    f.write(solution)
                print("SUCCESS")
            else:
                print("FAILED")
        except Exception as e:
            print(f"ERROR: {e}")
