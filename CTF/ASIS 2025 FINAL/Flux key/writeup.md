# FluxKey - ASIS CTF Crypto Challenge Writeup

## Challenge Overview

We're given a custom symmetric cipher called "FluxKey" that encrypts a flag. We have access to:
- **Encrypt flag**: Get the encrypted flag
- **Decrypt oracle**: Decrypt arbitrary ciphertexts (with restrictions)
- **Change IV**: Modify the initialization vector
- **Get parameters**: View current IV and TIPS values

## Cipher Analysis

### Encryption Algorithm

```python
def encrypt(msg: bytes, key: bytes) -> bytes:
    msg = pad(msg)
    MSG = [msg[4*k:4*k + 4] for k in range(len(msg) // 4)]
    enc, KEY = b'', bytes_to_long(key)
    
    for block in MSG:
        key, msg = KEY, bytes_to_long(block)
        for _ in range(1424):  # rounds
            # Extract 5 bits from msg at positions defined by TIPS
            _key = (msg >> TIPS[0]) & 1 | (msg >> TIPS[1]) & 2 | \
                   (msg >> TIPS[2]) & 4 | (msg >> TIPS[3]) & 8 | \
                   (msg >> TIPS[4]) & 16
            
            # Compute new head bit
            head = (msg >> 16 & 1) ^ (msg & 1) ^ (IV >> _key & 1) ^ (key & 1)
            
            # LFSR shift
            msg = head << 31 | msg >> 1
            key = (key & 1) << 63 | key >> 1
        enc += long_to_bytes(msg).zfill(4)
    return enc
```

Key observations:
1. **Block cipher**: Processes 4-byte blocks independently
2. **LFSR structure**: Each round shifts msg right by 1, inserting computed head bit
3. **IV dependency**: The head bit XORs with `(IV >> _key & 1)` where `_key` depends on plaintext bits
4. **Key schedule**: Key also rotates each round (64-bit LFSR)

### Oracle Restrictions

```python
def validate_enc(_enc, __enc):
    if len(_enc) % 4 != 0 or \
       len(_enc) >= len(__enc) or \
       any(_enc[i:i + 4] in __enc for i in range(0, len(_enc), 4)):
        return False
    return True
```

We **cannot** directly decrypt any 4-byte block that appears in the flag ciphertext.

## The Vulnerability: Linearity

The crucial insight is that this cipher is **linear** (or more precisely, affine) with respect to XOR operations on the plaintext/ciphertext.

When IV is fixed, the encryption function E satisfies:
```
E(P₁ ⊕ P₂) = E(P₁) ⊕ E(P₂) ⊕ E(0)
```

Equivalently for decryption:
```
D(C₁ ⊕ C₂) = D(C₁) ⊕ D(C₂) ⊕ D(0)
```

### Why is it linear?

Looking at the head bit computation:
```python
head = (msg >> 16 & 1) ^ (msg & 1) ^ (IV >> _key & 1) ^ (key & 1)
```

This is purely XOR operations. The LFSR shift `msg = head << 31 | msg >> 1` is also linear over GF(2). The only non-linear component is `_key` selection based on msg bits, but when we set IV = 0xFFFFFFFF, then `(IV >> _key & 1) = 1` for ALL values of `_key` (0-31), making the IV contribution constant!

## Attack Strategy

Given the linearity property, we can recover any flag block without directly decrypting it:

1. **Set IV = 0xFFFFFFFF** to make behavior deterministic
2. **Get flag ciphertext** blocks: C_flag[0], C_flag[1], ...
3. **Compute D(0)** by decrypting the zero block (0x00000000)
4. **For each flag block C_flag:**
   - Choose arbitrary C_arb not in flag ciphertext
   - Compute C_combined = C_flag ⊕ C_arb
   - Decrypt both C_arb and C_combined (both allowed by oracle)
   - Use linearity: **D(C_flag) = D(C_combined) ⊕ D(C_arb) ⊕ D(0)**

## Solution Script

```python
#!/usr/bin/env python3
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
    
    # Setup
    iv, tips = get_params()
    print(f"[*] IV: {hex(iv)}, TIPS: {tips}")
    
    # Set IV to all 1s for consistent behavior
    set_iv(0xFFFFFFFF)
    
    # Get flag ciphertext
    flag_enc = encrypt_flag()
    flag_blocks = [flag_enc[i:i+4] for i in range(0, len(flag_enc), 4)]
    print(f"[*] Flag has {len(flag_blocks)} blocks")
    
    # Decrypt zero block
    D_zero = decrypt_block(b'\x00\x00\x00\x00', flag_blocks)
    D_zero_int = int.from_bytes(D_zero, 'big')
    print(f"[*] D(0) = {hexlify(D_zero).decode()}")
    
    # Recover each flag block using linearity
    flag = b''
    for i, C_flag in enumerate(flag_blocks):
        C_flag_int = int.from_bytes(C_flag, 'big')
        
        # Find valid C_arb
        C_arb_int = 0x12345678
        while True:
            C_arb = C_arb_int.to_bytes(4, 'big')
            C_combined_int = C_flag_int ^ C_arb_int
            C_combined = C_combined_int.to_bytes(4, 'big')
            if C_arb not in flag_blocks and C_combined not in flag_blocks:
                break
            C_arb_int += 1
        
        # Decrypt and apply linearity
        D_arb = decrypt_block(C_arb, flag_blocks)
        D_combined = decrypt_block(C_combined, flag_blocks)
        
        D_arb_int = int.from_bytes(D_arb, 'big')
        D_combined_int = int.from_bytes(D_combined, 'big')
        
        # D(C_flag) = D(C_combined) ⊕ D(C_arb) ⊕ D(0)
        P_flag_int = D_combined_int ^ D_arb_int ^ D_zero_int
        P_flag = P_flag_int.to_bytes(4, 'big')
        
        flag += P_flag
        print(f"[+] Block {i}: {P_flag}")
    
    print(f"\n[+] Flag: {flag.rstrip(b'+').decode()}")
    r.close()

if __name__ == '__main__':
    solve()
```

## Mathematical Proof of Linearity

Let's prove that D(C₁ ⊕ C₂) = D(C₁) ⊕ D(C₂) ⊕ D(0) when IV = 0xFFFFFFFF.

For a single round with IV all-ones:
- `(IV >> _key & 1) = 1` for any `_key ∈ [0, 31]`

The head bit becomes:
```
head = (msg >> 16 & 1) ^ (msg & 1) ^ 1 ^ (key & 1)
```

This is an **affine** function of msg bits. The full LFSR transformation over 1424 rounds is a composition of affine transformations, which remains affine:

```
E(P) = A·P ⊕ b
```

where A is a linear transformation matrix over GF(2) and b is a constant vector.

Therefore:
```
E(P₁) ⊕ E(P₂) = (A·P₁ ⊕ b) ⊕ (A·P₂ ⊕ b) = A·(P₁ ⊕ P₂)
E(P₁ ⊕ P₂) = A·(P₁ ⊕ P₂) ⊕ b
```

So: `E(P₁ ⊕ P₂) = E(P₁) ⊕ E(P₂) ⊕ b = E(P₁) ⊕ E(P₂) ⊕ E(0)`

The same applies to decryption since D = E⁻¹ is also affine.

## Key Takeaways

1. **LFSR-based ciphers are often linear** over GF(2), making them vulnerable to algebraic attacks
2. **Oracle restrictions can be bypassed** if the underlying function has algebraic properties
3. **Setting IV to special values** (all 0s, all 1s) can simplify analysis by removing data-dependent behavior
4. **Affine self-similarity**: D(C₁ ⊕ C₂) ⊕ D(0) = D(C₁) ⊕ D(C₂) ⊕ D(0) ⊕ D(0) = D(C₁) ⊕ D(C₂)

## Flag

```
ASIS{...}
```

(Run the script against the live server to get the actual flag)
