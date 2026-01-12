#!/usr/bin/env python3
"""
FluxKey CTF Challenge Solution
ASIS CTF 2024/2025

The key insight is that the cipher is LINEAR with respect to the plaintext 
when IV is fixed. This means:
    E(P1 ^ P2) = E(P1) ^ E(P2) ^ E(0)

Or equivalently:
    D(C1 ^ C2) = D(C1) ^ D(C2) ^ D(0)

So if we want to decrypt a flag block C_flag:
1. Choose an arbitrary ciphertext C_arb that's not in flag
2. Compute C_combined = C_flag ^ C_arb
3. If C_combined is also not in flag, decrypt both C_arb and C_combined
4. Then: D(C_flag) = D(C_combined) ^ D(C_arb) ^ D(0)

This bypasses the restriction that we can't directly decrypt flag blocks!
"""

from pwn import *
from binascii import hexlify, unhexlify

def solve():
    r = remote('65.109.194.34', 13337)
    
    def get_params():
        r.sendlineafter(b'[Q]uit\n', b'g')
        r.recvuntil(b'IV = ')
        iv = int(r.recvline().strip())
        r.recvuntil(b'TIPS = ')
        tips = eval(r.recvline().strip())
        return iv, tips
    
    def encrypt_flag():
        r.sendlineafter(b'[Q]uit\n', b'e')
        r.recvuntil(b"_flag_enc = b'")
        return unhexlify(r.recvuntil(b"'")[:-1])
    
    def set_iv(iv_val):
        r.sendlineafter(b'[Q]uit\n', b'c')
        r.sendlineafter(b'?', b'i')
        r.sendlineafter(b'hex:', f'{iv_val:08x}'.encode())
        r.recvline()
    
    def decrypt_block(block_bytes, flag_blocks):
        """Decrypt a single 4-byte block, returns None if block is in flag"""
        if block_bytes in flag_blocks:
            return None
        
        r.sendlineafter(b'[Q]uit\n', b'd')
        r.sendlineafter(b'hex:', hexlify(block_bytes))
        r.recvuntil(b'\xe2\x94\x83 ')
        line = r.recvline().decode()
        
        if '_msg' not in line:
            return None
        
        try:
            return eval(line.split('= ')[1].strip())
        except:
            return None
    
    # Get parameters
    iv, tips = get_params()
    print(f"[*] IV: {hex(iv)}, TIPS: {tips}")
    
    # Set IV to a known value for consistent behavior
    # Using 0xFFFFFFFF means (IV >> _key & 1) = 1 for all _key values
    set_iv(0xFFFFFFFF)
    
    # Get flag ciphertext
    flag_enc = encrypt_flag()
    flag_blocks = [flag_enc[i:i+4] for i in range(0, len(flag_enc), 4)]
    print(f"[*] Flag has {len(flag_blocks)} blocks")
    print(f"[*] Flag ciphertext: {hexlify(flag_enc).decode()}")
    
    # First, decrypt the "zero" block for our XOR calculations
    # D(0) is needed for the linearity equation
    zero_ct = b'\x00\x00\x00\x00'
    if zero_ct in flag_blocks:
        # Use a different base if zero is in flag (unlikely)
        zero_ct = b'\xff\xff\xff\xff'
    
    D_zero = decrypt_block(zero_ct, flag_blocks)
    if D_zero is None:
        print("[-] Could not decrypt zero block")
        return
    
    D_zero_int = int.from_bytes(D_zero, 'big')
    print(f"[*] D(0x00000000) = {hexlify(D_zero).decode()}")
    
    # For each flag block, use linearity to recover plaintext
    flag = b''
    
    for i, C_flag in enumerate(flag_blocks):
        C_flag_int = int.from_bytes(C_flag, 'big')
        
        # Choose C_arb that's not in flag_blocks
        # Start with a simple value and increment if needed
        C_arb_int = 0x12345678
        while True:
            C_arb = C_arb_int.to_bytes(4, 'big')
            C_combined_int = C_flag_int ^ C_arb_int
            C_combined = C_combined_int.to_bytes(4, 'big')
            
            if C_arb not in flag_blocks and C_combined not in flag_blocks:
                break
            C_arb_int += 1
        
        # Decrypt C_arb and C_combined
        D_arb = decrypt_block(C_arb, flag_blocks)
        D_combined = decrypt_block(C_combined, flag_blocks)
        
        if D_arb is None or D_combined is None:
            print(f"[-] Block {i}: decryption failed")
            flag += b'????'
            continue
        
        D_arb_int = int.from_bytes(D_arb, 'big')
        D_combined_int = int.from_bytes(D_combined, 'big')
        
        # Linearity: D(C_flag) = D(C_combined) ^ D(C_arb) ^ D(0)
        # Because C_combined = C_flag ^ C_arb
        # And E is linear, so D(C1 ^ C2) = D(C1) ^ D(C2) ^ D(0)
        # Therefore: D(C_flag ^ C_arb) = D(C_flag) ^ D(C_arb) ^ D(0)
        # Rearranging: D(C_flag) = D(C_flag ^ C_arb) ^ D(C_arb) ^ D(0)
        
        P_flag_int = D_combined_int ^ D_arb_int ^ D_zero_int
        P_flag = P_flag_int.to_bytes(4, 'big')
        
        flag += P_flag
        print(f"[+] Block {i}: {P_flag}")
    
    print(f"\n[+] Flag: {flag}")
    
    # Try to decode as ASCII, removing padding
    try:
        flag_str = flag.rstrip(b'+').decode('utf-8', errors='replace')
        print(f"[+] Flag (decoded): {flag_str}")
    except:
        pass
    
    r.close()

if __name__ == '__main__':
    solve()
